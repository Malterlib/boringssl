/* Copyright (c) 2015, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#ifdef DMalterlib
#include <Mib/Core/Core>
#endif

#include "internal.h"

#if defined(OPENSSL_MALTERLIB_THREADS)

#include <openssl/mem.h>
#include <openssl/type_check.h>

namespace {
  struct CMalterlibLock : public CMutualManyRead {
    CMalterlibLock();
    ~CMalterlibLock();
    
    DLinkDS_Link(CMalterlibLock, m_Link);
  };

  struct CSubSystem_BoringSSL : public CSubSystem {
    // Thread sanitizer has a limited amount of tracked locks, so this will exhaust that...
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
      for (auto &Mutex : m_Mutexes) {
        Mutex.f_PrepareFork();
      }
#endif
    }
    
    void f_ForkedParent() override {
#ifndef DMibSanitizerEnabled_Thread
      for (auto &Mutex : m_Mutexes) {
        Mutex.f_ForkedParent();
        Mutex.f_Unlock();
      }
#endif
      m_Lock.f_ForkedParent();
      m_Lock.f_Unlock();
    }
    
    void f_ForkedChild() override {
#ifndef DMibSanitizerEnabled_Thread
      for (auto &Mutex : m_Mutexes) {
        Mutex.f_ForkedChild();
        Mutex.f_Unlock();
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
    DLinkDS_List(CMalterlibLock, m_Link) m_Mutexes;
    TCVector<CCleanupEntry> m_CleanupFunctions;
  };
  
  constinit TCSubSystem<CSubSystem_BoringSSL, ESubSystemDestruction_BeforeMemoryManager>
    g_SubSystem_BoringSSL = {DAggregateInit};

  CMalterlibLock::CMalterlibLock() {
    auto &SubSystem = *g_SubSystem_BoringSSL;
    DLock(SubSystem.m_Lock);
    SubSystem.m_Mutexes.f_Insert(this);
  }
  
  CMalterlibLock::~CMalterlibLock() {
    auto &SubSystem = *g_SubSystem_BoringSSL;
    DLock(SubSystem.m_Lock);
    SubSystem.m_Mutexes.f_Remove(this);
  }

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

using CStaticLock = TCAggregate<CMalterlibLock, 125, CLowLevelLockAggregate>;

static_assert(sizeof(CRYPTO_STATIC_MUTEX) >= sizeof(CStaticLock), "Incorrect size");
static_assert(sizeof(CRYPTO_MUTEX) >= sizeof(CMalterlibLock), "Incorrect size");

struct CInitOnce {
  CLowLevelLockAggregate m_Lock;
  TCAtomic<bool> m_bInited;
};

static_assert(sizeof(CRYPTO_once_t) >= sizeof(CInitOnce), "Incorrect size");

void CRYPTO_once(CRYPTO_once_t *once, void (*init)(void)) {
  CInitOnce *pInit = fg_AutoReinterpretCast(once);
  if (pInit->m_bInited.f_Load(EMemoryOrder_Acquire))
    return;

  DLock(pInit->m_Lock);
  if (!pInit->m_bInited.f_Load()) {
    init();
    pInit->m_bInited.f_Store(true);
  }
}

void CRYPTO_add_cleanup(void (*cleanup)(void *), void *context) {
  auto &SubSystem = *g_SubSystem_BoringSSL;
  DLock(SubSystem.m_Lock);
  auto &Cleanup = SubSystem.m_CleanupFunctions.f_Insert();
  Cleanup.m_fCleanup = cleanup;
  Cleanup.m_pContext = context;
}

void CRYPTO_MUTEX_init(CRYPTO_MUTEX *lock) {
  new ((void *)lock) CMalterlibLock();
}

void CRYPTO_MUTEX_lock_read(CRYPTO_MUTEX *lock) {
  CMalterlibLock *pLock = fg_AutoReinterpretCast(lock);
  pLock->f_LockRead();
}

void CRYPTO_MUTEX_lock_write(CRYPTO_MUTEX *lock) {
  CMalterlibLock *pLock = fg_AutoReinterpretCast(lock);
  pLock->f_Lock();
}

void CRYPTO_MUTEX_unlock_read(CRYPTO_MUTEX *lock) {
  CMalterlibLock *pLock = fg_AutoReinterpretCast(lock);
  pLock->f_UnlockRead();
}

void CRYPTO_MUTEX_unlock_write(CRYPTO_MUTEX *lock) {
  CMalterlibLock *pLock = fg_AutoReinterpretCast(lock);
  pLock->f_Unlock();
}

void CRYPTO_MUTEX_cleanup(CRYPTO_MUTEX *lock) {
  CMalterlibLock *pLock = fg_AutoReinterpretCast(lock);
  pLock->~CMalterlibLock();
}

void CRYPTO_STATIC_MUTEX_lock_read(struct CRYPTO_STATIC_MUTEX *lock) {
  CStaticLock *pLock = fg_AutoReinterpretCast(lock);
  (*pLock)->f_LockRead();
}

void CRYPTO_STATIC_MUTEX_lock_write(struct CRYPTO_STATIC_MUTEX *lock) {
  CStaticLock *pLock = fg_AutoReinterpretCast(lock);
  (*pLock)->f_Lock();
}

void CRYPTO_STATIC_MUTEX_unlock_read(struct CRYPTO_STATIC_MUTEX *lock) {
  CStaticLock *pLock = fg_AutoReinterpretCast(lock);
  (*pLock)->f_UnlockRead();
}

void CRYPTO_STATIC_MUTEX_unlock_write(struct CRYPTO_STATIC_MUTEX *lock) {
  CStaticLock *pLock = fg_AutoReinterpretCast(lock);
  (*pLock)->f_Unlock();
}

struct COpenSSLThreadLocals {
  void *m_Pointers[NUM_OPENSSL_THREAD_LOCALS] = {0};
  thread_local_destructor_t m_Destructors[NUM_OPENSSL_THREAD_LOCALS] = {0};

  ~COpenSSLThreadLocals() {
    for (mint i = 0; i < NUM_OPENSSL_THREAD_LOCALS; ++i) {
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

#endif  /* OPENSSL_MALTERLIB_THREADS */
