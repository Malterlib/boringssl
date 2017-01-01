// Copyright 2015 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "internal.h"

#if defined(OPENSSL_MALTERLIB_THREADS)

#include <openssl/mem.h>
#include <openssl/type_check.h>


BSSL_NAMESPACE_BEGIN

namespace {
  struct CSubSystem_BoringSSL : public CSubSystem {
    // f_PrepareFork skips acquiring all mutexes under ThreadSanitizer to avoid
    // exhausting its lock table.
    void f_PrepareFork() override {
#ifndef DMibSanitizerEnabled_Thread
      while (true)
      {
#endif
        m_Lock.f_Lock();
#ifndef DMibSanitizerEnabled_Thread
        bool bAborted = false;
        for (auto iMutex = m_Mutexes.f_GetIterator(); iMutex; ++iMutex) {
          if (!iMutex->f_TryLock()) {
            --iMutex;
            bAborted = true;
            for (; iMutex; --iMutex)
              iMutex->f_Unlock();
            m_Lock.f_Unlock();
            break;
          }
        }
        if (!bAborted)
          break;
      }
#endif
      m_Lock.f_PrepareFork();
#ifndef DMibSanitizerEnabled_Thread
      for (auto &Lock : m_Mutexes) {
        Lock.f_PrepareFork();
      }
#endif
    }

    void f_ForkedParent() override {
#ifndef DMibSanitizerEnabled_Thread
      for (auto &Lock : m_Mutexes) {
        Lock.f_ForkedParent();
        Lock.f_Unlock();
      }
#endif
      m_Lock.f_ForkedParent();
      m_Lock.f_Unlock();
    }

    void f_ForkedChild() override {
#ifndef DMibSanitizerEnabled_Thread
      for (auto &Lock : m_Mutexes) {
        Lock.f_ForkedChild();
        Lock.f_Unlock();
      }
#endif
      m_Lock.f_ForkedChild();
      m_Lock.f_Unlock();
    }

    void f_DoCleanup() {
      for (auto &Cleanup : m_CleanupFunctions) {
        Cleanup.m_fCleanup(Cleanup.m_pContext);
      }
      m_CleanupFunctions.f_Clear();
    }

    CSubSystem_BoringSSL();

    ~CSubSystem_BoringSSL() {
      DMibRequire(m_CleanupFunctions.f_IsEmpty());
    }

    struct CCleanupEntry {
      void (*m_fCleanup)(void *);
      void *m_pContext;
    };

    CMutual m_Lock;
    DLinkDS_List(MalterlibLock, m_Link) m_Mutexes;
    TCVector<CCleanupEntry> m_CleanupFunctions;
  };

  constinit TCSubSystem<CSubSystem_BoringSSL, ESubSystemDestruction_BeforeMemoryManager>
    g_SubSystem_BoringSSL = {DAggregateInit};

  struct CSubSystem_BoringSSL_Cleanup {
    ~CSubSystem_BoringSSL_Cleanup(){
      g_SubSystem_BoringSSL->f_DoCleanup();
    }
  };

  constinit TCAggregate<CSubSystem_BoringSSL_Cleanup, 127, CLowLevelLockAggregate> g_DoCleanup = {DAggregateInit};

  CSubSystem_BoringSSL::CSubSystem_BoringSSL() {
    *g_DoCleanup;
  }
}

MalterlibLock::MalterlibLock() {
  auto &SubSystem = *g_SubSystem_BoringSSL;
  DLock(SubSystem.m_Lock);
  SubSystem.m_Mutexes.f_Insert(this);
}

MalterlibLock::~MalterlibLock() {
  auto &SubSystem = *g_SubSystem_BoringSSL;
  DLock(SubSystem.m_Lock);
  SubSystem.m_Mutexes.f_Remove(this);
}

void CRYPTO_once(CRYPTO_once_t *once, void (*init)()) {
  if (once->m_bInited.f_Load(NAtomic::gc_MemoryOrder_Acquire))
    return;

  DLock(once->m_Lock);
  if (!once->m_bInited.f_Load()) {
    init();
    once->m_bInited.f_Store(true);
  }
}

struct COpenSSLThreadLocals {
  void *m_Pointers[NUM_OPENSSL_THREAD_LOCALS] = {0};
  thread_local_destructor_t m_Destructors[NUM_OPENSSL_THREAD_LOCALS] = {0};

  ~COpenSSLThreadLocals() {
    for (umint i = 0; i < NUM_OPENSSL_THREAD_LOCALS; ++i) {
      if (m_Pointers[i] && m_Destructors[i])
        m_Destructors[i](m_Pointers[i]);
    }
  }
};

constinit TCAggregate<TCThreadLocal<COpenSSLThreadLocals>, 126>
  g_OpenSSLThreadLocals = {DAggregateInit};

void *CRYPTO_get_thread_local(thread_local_data_t index) {
  auto &ThreadLocals = **g_OpenSSLThreadLocals;
  DFastCheck(index >= 0 && index < NUM_OPENSSL_THREAD_LOCALS);
  return ThreadLocals.m_Pointers[index];
}

int CRYPTO_set_thread_local(thread_local_data_t index, void *value,
                            thread_local_destructor_t destructor) {

  auto &ThreadLocals = **g_OpenSSLThreadLocals;
  DFastCheck(index >= 0 && index < NUM_OPENSSL_THREAD_LOCALS);
  DFastCheck(ThreadLocals.m_Pointers[index] == nullptr);
  ThreadLocals.m_Pointers[index] = value;
  ThreadLocals.m_Destructors[index] = destructor;
  return 1;
}

BSSL_NAMESPACE_END

#endif  // OPENSSL_MALTERLIB_THREADS
