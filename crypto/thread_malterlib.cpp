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

using CStaticLock = TCAggregate<CMutualManyRead, 128, CSpinLockAggregate>;

static_assert(sizeof(CRYPTO_STATIC_MUTEX) >= sizeof(CStaticLock), "Incorrect size");
static_assert(sizeof(CRYPTO_MUTEX) >= sizeof(CMutualManyRead), "Incorrect size");

struct CInitOnce {
  CSpinLockAggregate m_Lock;
  size_t m_bInited;
};

static_assert(sizeof(CRYPTO_once_t) >= sizeof(CInitOnce), "Incorrect size");

void CRYPTO_once(CRYPTO_once_t *once, void (OPENSSL_CDECL * init)(void)) {
  CInitOnce *pInit = fg_AutoReinterpretCast(once);
  DLock(pInit->m_Lock);
  if (!pInit->m_bInited) {
    init();
    pInit->m_bInited = true;
  }
}

void CRYPTO_MUTEX_init(CRYPTO_MUTEX *lock) {
  new ((void *)lock) CMutualManyRead();
}

void CRYPTO_MUTEX_lock_read(CRYPTO_MUTEX *lock) {
  CMutualManyRead *pLock = fg_AutoReinterpretCast(lock);
  pLock->f_LockRead();
}

void CRYPTO_MUTEX_lock_write(CRYPTO_MUTEX *lock) {
  CMutualManyRead *pLock = fg_AutoReinterpretCast(lock);
  pLock->f_Lock();
}

void CRYPTO_MUTEX_unlock_read(CRYPTO_MUTEX *lock) {
  CMutualManyRead *pLock = fg_AutoReinterpretCast(lock);
  pLock->f_UnlockRead();
}

void CRYPTO_MUTEX_unlock_write(CRYPTO_MUTEX *lock) {
  CMutualManyRead *pLock = fg_AutoReinterpretCast(lock);
  pLock->f_Unlock();
}

void CRYPTO_MUTEX_cleanup(CRYPTO_MUTEX *lock) {
  CMutualManyRead *pLock = fg_AutoReinterpretCast(lock);
  pLock->~CMutualManyRead();
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

TCAggregate<TCThreadLocal<COpenSSLThreadLocals>> g_OpenSSLThreadLocals = {DAggregateInit};

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
