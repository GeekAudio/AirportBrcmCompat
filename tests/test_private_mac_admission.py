"""Compile the actual CAS admission header and exercise real competing threads."""
import pathlib
import subprocess
import tempfile
import unittest

PROJECT = pathlib.Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "admission.hpp"
#include <assert.h>
#include <stdlib.h>
#include <atomic>
#include <thread>
#include <vector>
#include <pthread.h>
using namespace PrivateMAC;
// Actual current user-thread identity, opaque and never printed. These are
// test threads, not invented kernel pointers or a kernel credential check.
static uintptr_t threadToken(){return reinterpret_cast<uintptr_t>(pthread_self());}
static const Binding target{11,22,1}; // Fictional controller/interface tokens.
static void bindings(){
 Admission a(target);AdmissionLease lease;Binding b=target;
 b.controller=0;assert(a.enter(b,threadToken(),lease)==EINVAL&&!lease.issued());
 b=target;b.controller++;assert(a.enter(b,threadToken(),lease)==ENXIO&&!lease.issued());
 b=target;b.primary++;assert(a.enter(b,threadToken(),lease)==ENXIO&&!lease.issued());
 b=target;b.generation++;assert(a.enter(b,threadToken(),lease)==ESTALE&&!lease.issued());
 assert(a.enter(target,0,lease)==EINVAL&&!lease.issued());
 Admission invalid(Binding{});assert(invalid.enter(target,threadToken(),lease)==EINVAL);
 assert(!a.isBusy()&&!a.isQuarantined()&&!a.quarantineReason());
}
static void ownership_and_replay(){
 Admission a(target),other(target);AdmissionLease one,empty;const auto me=threadToken();
 assert(!a.enter(target,me,one)&&one.issued()&&a.isBusy());
 assert(a.enter(target,me,empty)==EBUSY&&!empty.issued()); // Same-thread reentry.
 assert(a.enter(target,me,one)==EINVAL); // Cannot overwrite a capability.
 assert(a.finish(one,0)==EPERM&&a.poison(one,0,7)==EPERM);
 assert(other.finish(one,me)==EINVAL&&other.poison(one,me,7)==EINVAL);
 assert(a.finish(empty,me)==EINVAL&&a.poison(empty,me,7)==EINVAL);
 const AdmissionLease stale=one;
 assert(!a.finish(one,me)&&!a.isBusy());
 assert(a.finish(one,me)==ESTALE&&a.poison(one,me,7)==ESTALE);
 AdmissionLease two;assert(!a.enter(target,me,two));
 assert(a.finish(stale,me)==ESTALE&&a.poison(stale,me,7)==ESTALE);
 assert(a.isBusy()&&!a.isQuarantined());assert(!a.finish(two,me));
}
static void persistent_quarantine(){
 Admission a(target);AdmissionLease lease;const auto me=threadToken();assert(!a.enter(target,me,lease));
 assert(!a.poison(lease,me,0x1234)&&a.isBusy()&&a.isQuarantined());
 assert(!a.poison(lease,me,0x5678)&&a.quarantineReason()==0x1234);
 assert(!a.finish(lease,me)&&!a.isBusy()&&a.isQuarantined()&&a.quarantineReason()==0x1234);
 AdmissionLease denied;assert(a.enter(target,me,denied)==EIO&&!denied.issued());
 Admission independent(Binding{11,22,2});AdmissionLease next;
 assert(!independent.enter(Binding{11,22,2},me,next));
 assert(independent.poison(lease,me,1)==EINVAL&&!independent.isQuarantined());
 assert(!independent.finish(next,me)&&a.isQuarantined());
}
static void contention(){
 Admission a(target);std::atomic<bool> go{false};std::atomic<unsigned> inside{0},success{0},busy{0};
 uint64_t protectedCounter=0;std::vector<std::thread> jobs;
 for(unsigned t=0;t<16;t++)jobs.emplace_back([&]{
  while(!go.load(std::memory_order_acquire))std::this_thread::yield();
  const auto me=threadToken();
  for(unsigned n=0;n<2000;n++){
   AdmissionLease lease;const int error=a.enter(target,me,lease);
   if(error){assert(error==EBUSY&&!lease.issued());busy++;std::this_thread::yield();continue;}
   assert(inside.fetch_add(1)==0);const auto before=protectedCounter;
   std::this_thread::yield();protectedCounter=before+1;
   assert(inside.fetch_sub(1)==1);success++;
   assert(!a.finish(lease,me));
  }
 });
 go.store(true,std::memory_order_release);for(auto &j:jobs)j.join();
 assert(success.load()>0&&busy.load()>0&&success+busy==32000);
 assert(protectedCounter==success&&!inside&&!a.isBusy()&&!a.isQuarantined());
}
static void foreign_thread_cannot_change_owner(){
 Admission a(target);AdmissionLease lease;std::atomic<bool> issued{false},finished{false};
 std::thread owner([&]{const auto me=threadToken();assert(!a.enter(target,me,lease));
  issued.store(true,std::memory_order_release);
  while(!finished.load(std::memory_order_acquire))std::this_thread::yield();
  assert(a.isBusy()&&!a.isQuarantined());assert(!a.finish(lease,me));
 });
 std::thread foreign([&]{while(!issued.load(std::memory_order_acquire))std::this_thread::yield();
  const auto me=threadToken();
  for(unsigned n=0;n<10000;n++){
   assert(a.finish(lease,me)==EPERM&&a.poison(lease,me,99)==EPERM);
   assert(a.isBusy()&&!a.isQuarantined());
  }
  finished.store(true,std::memory_order_release);
 });owner.join();foreign.join();assert(!a.isBusy()&&!a.isQuarantined());
}
static void quarantine_visibility(){
 Admission a(target);AdmissionLease lease;const auto me=threadToken();assert(!a.enter(target,me,lease));
 std::atomic<unsigned> observed{0};std::vector<std::thread> readers;
 for(unsigned t=0;t<8;t++)readers.emplace_back([&]{
  // Observe the actual release/acquire quarantine publication, without an
  // auxiliary 'poison done' flag that could accidentally mask its ordering.
  while(!a.isQuarantined())std::this_thread::yield();
  assert(a.quarantineReason()==0x1357);AdmissionLease refused;
  assert(a.enter(target,threadToken(),refused)==EIO&&!refused.issued());observed++;
 });
 assert(!a.poison(lease,me,0x1357));
 for(auto &r:readers)r.join();assert(observed==8&&a.isBusy());
 assert(!a.finish(lease,me));assert(!a.isBusy()&&a.isQuarantined()&&a.quarantineReason()==0x1357);
}
static void one_common_cas_after_false_hints(){
 Admission a(target);std::atomic<unsigned> ready{0},attempted{0},won{0},refused{0};
 std::atomic<bool> go{false};std::vector<std::thread> jobs;
 for(unsigned t=0;t<16;t++)jobs.emplace_back([&,t]{
  const unsigned requestKind=t%3; // Native private, native nonprivate, legacy.
  (void)requestKind; // Adapter must route all three through this same API.
  assert(!a.isBusy());ready++;
  while(!go.load(std::memory_order_acquire))std::this_thread::yield();
  AdmissionLease lease;const auto me=threadToken();const int error=a.enter(target,me,lease);
  if(!error){won++;attempted++;while(attempted.load()!=16)std::this_thread::yield();assert(!a.finish(lease,me));}
  else{assert(error==EBUSY&&!lease.issued());refused++;attempted++;}
 });
 while(ready.load()!=16)std::this_thread::yield();go.store(true,std::memory_order_release);
 for(auto &j:jobs)j.join();assert(won==1&&refused==15&&!a.isBusy());
}
int main(int argc,char **argv){assert(argc==2);switch(atoi(argv[1])){
 case 0:bindings();break;case 1:ownership_and_replay();break;case 2:persistent_quarantine();break;
 case 3:contention();break;case 4:foreign_thread_cannot_change_owner();break;
 case 5:quarantine_visibility();break;case 6:one_common_cas_after_false_hints();break;default:abort();}}
'''


class PrivateMACAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="private-mac-admission-", dir="/private/tmp")
        cls.binary = pathlib.Path(cls.tmp.name) / "test"
        cls.build(cls.binary, "address,undefined")

    @classmethod
    def build(cls, binary, sanitizers):
        r = subprocess.run(
            ["xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror", "-pthread",
             "-fsanitize=" + sanitizers, "-fno-omit-frame-pointer",
             "-I", str(PROJECT / "src/private_mac_compat"), "-x", "c++", "-", "-o", str(binary)],
            input=HARNESS, capture_output=True, text=True, timeout=60)
        if r.returncode:
            raise AssertionError(r.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def scenario(self, n):
        r = subprocess.run([str(self.binary), str(n)], capture_output=True, text=True, timeout=20)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_exact_controller_primary_generation_and_thread_required(self): self.scenario(0)
    def test_owner_reentry_cross_instance_and_stale_ticket(self): self.scenario(1)
    def test_finishing_busy_never_clears_first_quarantine(self): self.scenario(2)
    def test_real_16_thread_contention_protects_shared_nonatomic_payload(self): self.scenario(3)
    def test_wrong_real_thread_cannot_finish_or_poison_owner(self): self.scenario(4)
    def test_release_acquire_quarantine_publishes_first_reason(self): self.scenario(5)
    def test_false_busy_observations_still_require_one_common_cas(self): self.scenario(6)

    def test_thread_sanitizer_for_all_concurrency_scenarios(self):
        binary = pathlib.Path(self.tmp.name) / "test-tsan"
        self.build(binary, "thread")
        for n in (3, 4, 5, 6):
            with self.subTest(scenario=n):
                r = subprocess.run([str(binary), str(n)], capture_output=True, text=True, timeout=20)
                self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
