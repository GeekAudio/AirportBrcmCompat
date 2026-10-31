"""Actual atomic admission core; host lifetime/concurrency contracts only."""
from pathlib import Path
import subprocess
import tempfile
import unittest

PROJECT=Path(__file__).resolve().parents[1]
HARNESS=r'''
#include "event_pipe_core.hpp"
#include <assert.h>
#include <atomic>
#include <thread>
#include <vector>
#include <stdlib.h>
using AWDLKernel::EventPipeCore;
using Phase=EventPipeCore::Phase;
static void open(EventPipeCore &c) {assert(c.beginCreate());assert(c.finishCreate(true));}
static void scenario(int n) {
 if(n==0) {
  EventPipeCore c;assert(c.phase()==Phase::Empty&&!c.release()&&!c.acquire());
  assert(c.beginCreate()&&!c.beginCreate()&&!c.acquire()&&!c.acquireCloser());
  assert(c.finishCreate(true)&&c.phase()==Phase::Open&&!c.finishCreate(true));
  assert(c.acquire()&&c.operations()==1);c.beginClose();
  assert(!c.acquire()&&!c.acquireCloser()&&c.phase()==Phase::Closing);
  assert(c.release()&&!c.release()&&c.operations()==0&&c.acquireCloser());
  assert(!c.acquireCloser()&&!c.acquire()&&c.finishClose(true));
  assert(c.phase()==Phase::Closed&&!c.beginCreate()&&!c.acquireCloser());
  c.beginClose();assert(c.phase()==Phase::Closed&&!c.finishClose(true));
 } else if(n==1) {
  EventPipeCore c;assert(c.beginCreate());c.beginClose();
  assert(!c.acquireCloser()&&!c.acquire());
  assert(!c.finishCreate(true)&&c.phase()==Phase::Closing);
  assert(c.acquireCloser()&&c.finishClose(true));
 } else if(n==2) {
  EventPipeCore c;assert(c.beginCreate());assert(!c.finishCreate(false));
  assert(c.phase()==Phase::Closing&&c.acquireCloser());
  assert(c.finishClose(false)&&c.phase()==Phase::Closing);
  assert(!c.beginCreate()&&c.acquireCloser()&&c.finishClose(true));
 } else if(n==3) {
  EventPipeCore c;c.beginClose();assert(c.phase()==Phase::Closed&&!c.beginCreate());
  assert(!c.finishCreate(false)&&!c.acquireCloser()&&!c.release());
 } else if(n==4) {
  EventPipeCore c;open(c);
  for(unsigned i=0;i<EventPipeCore::MaximumOperations;++i)assert(c.acquire());
  assert(!c.acquire()&&c.operations()==EventPipeCore::MaximumOperations);
  c.beginClose();assert(!c.acquireCloser());
  for(unsigned i=0;i<EventPipeCore::MaximumOperations;++i)assert(c.release());
  assert(!c.release()&&c.acquireCloser()&&c.finishClose(true));
 } else if(n==5) {
  for(int round=0;round<100;++round) {
   EventPipeCore c;assert(c.beginCreate());std::atomic<unsigned> started{0};
   std::thread a([&]{++started;c.beginClose();});
   std::thread b([&]{++started;c.finishCreate(true);});
   a.join();b.join();assert(started==2&&c.phase()==Phase::Closing);
   assert(c.acquireCloser()&&c.finishClose(true));
  }
 } else if(n==6) {
  EventPipeCore c;open(c);std::atomic<bool> go{false},freed{false};
  std::atomic<unsigned> admitted{0},inside{0};std::vector<std::thread> workers;
  for(int t=0;t<8;++t)workers.emplace_back([&]{
   while(!go.load())std::this_thread::yield();
   for(int i=0;i<2000;++i) {
    if(c.acquire()) {++admitted;++inside;assert(!freed.load());
     std::this_thread::yield();assert(!freed.load());--inside;assert(c.release());
    }
   }
  });
  go=true;while(admitted.load()<8)std::this_thread::yield();c.beginClose();
  while(!c.acquireCloser())std::this_thread::yield();
  assert(inside==0);freed=true;assert(c.finishClose(true));
  for(auto &w:workers)w.join();
  assert(c.operations()==0&&!c.acquire()&&c.phase()==Phase::Closed);
 } else if(n==7) {
  EventPipeCore c;open(c);c.beginClose();std::atomic<bool> go{false};
  std::atomic<unsigned> won{0};std::vector<std::thread> closers;
  for(int t=0;t<8;++t) {closers.emplace_back([&]{
   while(!go.load())std::this_thread::yield();
   if(c.acquireCloser()) {++won;std::this_thread::yield();assert(c.finishClose(true));}
  });}
  go=true;for(auto &w:closers)w.join();assert(won==1&&c.phase()==Phase::Closed);
 } else abort();
}
int main(int argc,char **argv) {assert(argc==2);scenario(atoi(argv[1]));}
'''

class EventPipeCoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder=tempfile.TemporaryDirectory(prefix='event-pipe-core-',dir='/private/tmp')
        cpp=Path(cls.folder.name)/'core.cpp';cls.binary=Path(cls.folder.name)/'core'
        cpp.write_text(HARNESS)
        compiled=subprocess.run(['xcrun','clang++','-std=c++14','-Wall','-Wextra','-Werror',
            '-pthread','-fsanitize=address,undefined','-fno-omit-frame-pointer',
            '-I',str(PROJECT/'src/awdl_kernel'),str(cpp),'-o',str(cls.binary)],
            capture_output=True,text=True)
        if compiled.returncode:raise AssertionError(compiled.stderr)
    @classmethod
    def tearDownClass(cls):cls.folder.cleanup()
    def check(self,index):subprocess.run([str(self.binary),str(index)],check=True,capture_output=True,timeout=30)
    def test_operation_blocks_destroy_and_closed_is_terminal(self):self.check(0)
    def test_close_racing_unfinished_allocation_cannot_destroy(self):self.check(1)
    def test_failed_create_and_busy_close_preserve_closing(self):self.check(2)
    def test_close_before_create_prevents_late_initialization(self):self.check(3)
    def test_operation_counter_bound_and_underflow(self):self.check(4)
    def test_create_close_race_never_reopens_a_closed_generation(self):self.check(5)
    def test_concurrent_admission_cannot_outlive_resource_destruction(self):self.check(6)
    def test_only_one_concurrent_closer_may_destroy(self):self.check(7)

if __name__=='__main__':unittest.main()
