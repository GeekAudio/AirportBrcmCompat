"""Host integration model for owner-PID result snapshots across child scans."""
import pathlib
import subprocess
import tempfile
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "legacy_wifi_compat/scan_aggregate.hpp"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>

namespace A=LegacyWiFi::ScanAggregate;
namespace B=LegacyWiFi::ScanBridge;

static void put16(uint8_t *p,uint16_t v){memcpy(p,&v,2);}
static void put32(uint8_t *p,uint32_t v){memcpy(p,&v,4);}
static void put64(uint8_t *p,uint64_t v){memcpy(p,&v,8);}
static uint32_t get32(const uint8_t *p){uint32_t v;memcpy(&v,p,4);return v;}
static void deallocate(void *p,size_t){free(p);}

struct Result {
 uint8_t header[B::KernelHeaderSize]{};
 uint8_t ies[12]{};
 uint8_t marker=0;
};
struct FakeManager {
 int ownerPID=0;
 Result results[4]{};
 size_t count=0,cursor=0;
 // Mirrors El Cap searchForPendingAndClearPid(pid): every startScan removes
 // that PID's old inner node and its unconsumed results before adding a new one.
 void startScan(int pid,const uint8_t *markers,size_t n){
  assert(pid>0&&n<=4);ownerPID=pid;count=n;cursor=0;
  for(size_t i=0;i<n;i++){
   Result &r=results[i];memset(&r,0,sizeof(r));r.marker=markers[i];
   put32(r.header,1);r.header[0x20]=markers[i];
   for(size_t j=0;j<sizeof(r.ies);j++)r.ies[j]=uint8_t(markers[i]+j);
   put16(r.header+B::IELengthOffset,sizeof(r.ies));
   put64(r.header+B::KernelIEPointerOffset,reinterpret_cast<uintptr_t>(r.ies));
  }
 }
 int getResult(int pid,const uint8_t **result){
  if(pid!=ownerPID||cursor>=count){*result=nullptr;return 5;}
  *result=results[cursor++].header;return 0;
 }
};

static void snapshotAll(FakeManager &manager,A::Store &store,int pid){
 for(;;){
  const uint8_t *header=nullptr;const int error=manager.getResult(pid,&header);
  if(error==5)return;
  assert(error==0&&header);
  uint8_t fixed[A::RecordSize]{};
  assert(A::snapshotKernelResult(header,B::KernelHeaderSize,fixed,sizeof(fixed))==0);
  assert(store.append(fixed,sizeof(fixed))==0);
  memset(fixed,0,sizeof(fixed));
 }
}

int main(){
 constexpr int ownerPID=73;
 A::Store store;assert(store.begin(ownerPID));
 auto *pool=(uint8_t*)calloc(1,A::StorageSize);assert(pool);
 store.setStorage(pool,{deallocate});
 FakeManager manager;
 const uint8_t first[]={0x11,0x22};
 manager.startScan(ownerPID,first,2);snapshotAll(manager,store,ownerPID);
 assert(store.count()==2);
 // Starting a second child clears the manager's only per-PID node. Without
 // the immediate snapshots above, the first child's results are irretrievable.
 const uint8_t second[]={0x33};
 manager.startScan(ownerPID,second,1);
 assert(manager.count==1&&manager.results[0].header[0x20]==0x33);
 snapshotAll(manager,store,ownerPID);assert(store.count()==3);
 store.finish();

 uint8_t out[A::RecordSize]{};bool managed=false;uint64_t token=0;
 assert(store.peek(ownerPID,out,sizeof(out),&managed,&token)==0&&managed&&token);
 const uint8_t expected[]={0x11,0x22,0x33};
 // Simulated copyOut failure releases the lease without advancing the cursor.
 assert(store.commit(ownerPID,token,false));
 memset(out,0,sizeof(out));managed=false;uint64_t retryToken=0;
 assert(store.peek(ownerPID,out,sizeof(out),&managed,&retryToken)==0&&managed);
 assert(get32(out)==1&&out[0x20]==expected[0]);
 assert(store.commit(ownerPID,retryToken,true));

 for(size_t i=1;i<3;i++){
  memset(out,0,sizeof(out));managed=false;token=0;
  assert(store.peek(ownerPID,out,sizeof(out),&managed,&token)==0&&managed);
  assert(out[0x20]==expected[i]);
  assert(store.commit(ownerPID,token,true));
 }
 managed=false;token=0;
 assert(store.peek(ownerPID,out,sizeof(out),&managed,&token)==EIO&&managed&&token==0);
 // EOF remains managed, so the Runtime must not fall back to the last child.
 assert(store.peek(ownerPID,out,sizeof(out),&managed,&token)==EIO&&managed);
 managed=true;assert(store.peek(ownerPID+1,out,sizeof(out),&managed,&token)==0&&!managed);

 // Cancellation is terminal: a later callback/result-drain error must not
 // overwrite ECANCELED with native EOF/EIO and trigger GET11 fallback.
 A::Store cancelled;assert(cancelled.begin(ownerPID));
 pool=(uint8_t*)calloc(1,A::StorageSize);assert(pool);
 cancelled.setStorage(pool,{deallocate});
 cancelled.finish(ECANCELED);cancelled.finish(EIO);
 assert(cancelled.error()==ECANCELED);
 managed=false;token=0;
 assert(cancelled.peek(ownerPID,out,sizeof(out),&managed,&token)==ECANCELED&&
        managed&&token==0);
 A::Store::destroy(cancelled.clear());

 // An old copyOut lease cannot consume a new scan's first result, even for
 // the same PID; lease cookies remain monotonic across clear/begin lifetimes.
 memset(out,0,sizeof(out));managed=false;
 auto detached=store.clear();assert(detached.storage);A::Store::destroy(detached);
 assert(store.begin(ownerPID));
 pool=(uint8_t*)calloc(1,A::StorageSize);assert(pool);store.setStorage(pool,{deallocate});
 uint8_t record[A::RecordSize]{};put32(record,1);record[0x20]=0x44;
 assert(store.append(record,sizeof(record))==0);store.finish();
 uint64_t newToken=0;assert(store.peek(ownerPID,out,sizeof(out),&managed,&newToken)==0&&managed);
 assert(!store.commit(ownerPID,retryToken,true));
 assert(store.cursor()==0&&store.commit(ownerPID,newToken,true)&&store.cursor()==1);
 A::Store::destroy(store.clear());

 // A newly allocated session Store gets a distinct cookie too, even when a
 // recycled interface address and the same owner PID are presented later.
 A::Store replacement;assert(replacement.begin(ownerPID));
 pool=(uint8_t*)calloc(1,A::StorageSize);assert(pool);
 replacement.setStorage(pool,{deallocate});
 assert(replacement.append(record,sizeof(record))==0);replacement.finish();
 uint64_t replacementToken=0;managed=false;
 assert(replacement.peek(ownerPID,out,sizeof(out),&managed,&replacementToken)==0&&managed);
 assert(replacementToken!=retryToken&&replacementToken!=newToken);
 assert(!replacement.commit(ownerPID,newToken,true)&&replacement.cursor()==0);
 assert(replacement.commit(ownerPID,replacementToken,true));
 A::Store::destroy(replacement.clear());

 // Error and capacity limits cannot expose a partial successful union.
 A::Store overflow;assert(overflow.begin(ownerPID));
 pool=(uint8_t*)calloc(1,A::StorageSize);assert(pool);overflow.setStorage(pool,{deallocate});
 for(size_t i=0;i<A::MaximumResults;i++)
  assert(overflow.append(record,sizeof(record))==0);
 assert(overflow.append(record,sizeof(record))==EOVERFLOW);
 overflow.finish(EOVERFLOW);managed=false;
 assert(overflow.peek(ownerPID,out,sizeof(out),&managed,&token)==EOVERFLOW&&managed);
 A::Store::destroy(overflow.clear());

 uint8_t bad[B::KernelHeaderSize]{};uint8_t fixed[A::RecordSize]{};
 assert(A::snapshotKernelResult(nullptr,sizeof(bad),fixed,sizeof(fixed))==EINVAL);
 assert(A::snapshotKernelResult(bad,sizeof(bad),fixed,sizeof(fixed))==EINVAL);
 put32(bad,1);put16(bad+B::IELengthOffset,B::MaximumIEBytes+1);
 assert(A::snapshotKernelResult(bad,sizeof(bad),fixed,sizeof(fixed))==EOVERFLOW);
 put16(bad+B::IELengthOffset,4);put64(bad+B::KernelIEPointerOffset,UINT64_MAX-3);
 assert(A::snapshotKernelResult(bad,sizeof(bad),fixed,sizeof(fixed))==EFAULT);
 return 0;
}
'''


class ScanAggregateTests(unittest.TestCase):
    def test_manager_clears_prior_pid_node_but_snapshot_union_survives(self):
        with tempfile.TemporaryDirectory(prefix="scan-aggregate-", dir="/private/tmp") as tmp:
            source = pathlib.Path(tmp) / "aggregate.cpp"
            binary = pathlib.Path(tmp) / "aggregate"
            source.write_text(HARNESS)
            build = subprocess.run(
                ["clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g",
                 "-I", str(PROJECT / "src"), str(source), "-o", str(binary)],
                text=True, capture_output=True, timeout=30)
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(binary)], text=True, capture_output=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)


if __name__ == "__main__":
    unittest.main()
