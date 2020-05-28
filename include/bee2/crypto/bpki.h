/*
*******************************************************************************
\file bpki.h
\brief STB 34.101.78 (a PKI profile): helpers
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2020.05.28
\version 2020.05.28
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

/*!
*******************************************************************************
\file bpki.h
\brief Поддержка СТБ 34.101.78 (bpki)
*******************************************************************************
*/

#ifndef __BEE2_BPKI_H
#define __BEE2_BPKI_H

#ifdef __cplusplus
extern "C" {
#endif

#include "bee2/defs.h"

/*!
*******************************************************************************
\file bpki.h

Реализованы следующие механизмы СТБ 34.101.78 (bpki):
-	EPK (EncryptedPrivateKey) --- управление контейнером с личным ключом;
-	ESS (EncryptedSecretShare) --- управление контейнером с частичным секретом.

Контейнер содержит защищенный объект (личный ключ или частичный секрет) одного
из трех уровней стойкости, соответствующие долговременные параметры
(они обязательно стандартные), а также параметры защиты. Защита выполняется
с помощью механизма PBKDF2 (см. функцию beltPBKDF2()). 
*******************************************************************************
*/

/*
*******************************************************************************
Контейнер с личным ключом 
*******************************************************************************
*/

/*!	\brief Размер контейнера с личным ключом

	Определяется размер контейнера с личным ключом уровня l.
	\pre l == 128 || l == 192 || l == 256.
	\return Размер контейнера.
*/
size_t bpkiEPK_keep(size_t l);

/*!	\brief Создание контейнера с личным ключом

	Личный ключ [privkey_len]privkey защищается на пароле [pwd_len]pwd
	c iter итерациями пересчета ключа защиты и синхропосылкой salt.
	Защищенный ключ возвращается в контейнере [cont_len]cont,
	где
		cont_len = bpkiEPK_keep(privkey_len * 4).
	\expect{ERR_BAD_INPUT} privkey_len == 32 || privkey_len == 48 ||
		privkey_len == 64.
	\expect{ERR_BAD_INPUT} iter >= 10000.
	\return ERR_OK, если контейнер успешно создан, и код ошибки в противном
	случае.
*/
err_t bpkiEPKEnc(
	octet cont[],			/*!< [out] контейнер */
	const octet privkey[],	/*!< [in] личный ключ */
	size_t privkey_len,		/*!< [in] длина ключа */
	const octet pwd[],		/*!< [in] пароль */
	size_t pwd_len,			/*!< [in] длина пароля (в октетах) */
	size_t iter,			/*!< [in] синхропосылка ("соль") */
	const octet salt[8]		/*!< [in] число итераций */
);

/*!	\brief Разбор контейнера с личным ключом

	Из контейнера [cont_len]cont извлекается личный	ключ [privkey_len]privkey,
	где
		privkey_len = 4 * bpkiEPK_keep^{-1}(cont_len).
	С личного ключа снимается защита на пароле [pwd_len]pwd. Параметры защиты 
	прочитываются из контейнера.
	\expect{ERR_BAD_INPUT} cont_len == bpkiEPK_keep(l), где l == 128 ||
		l == 192 || l == 256.
	\return ERR_OK, если контейнер успешно разобран, и код ошибки в противном
	случае.
*/
err_t bpkiEPKDec(
	octet privkey[],		/*!< [out] личный ключ */
	octet cont[],			/*!< [in] контейнер */
	size_t cont_len,		/*!< [in] размер контейнера */
	const octet pwd[],		/*!< [in] пароль */
	size_t pwd_len			/*!< [in] длина пароля */
);

/*
*******************************************************************************
Контейнер с частичным секретом
*******************************************************************************
*/

/*!	\brief Размер контейнера с частичным секретом

	Определяется размер контейнера с частичным секретом уровня l.
	\pre l == 128 || l == 192 || l == 256.
	\return Размер контейнера.
*/
size_t bpkiESS_keep(size_t l);

/*!	\brief Создание контейнера с частичным секретом

	Частичный секрет [share_len]share защищается на пароле [pwd_len]pwd
	c iter итерациями пересчета ключа защиты и синхропосылкой salt.
	Защищенный секрет возвращается в контейнере [cont_len]cont,
	где
		cont_len = bpkiESS_keep((share_len - 1) * 8).
	\expect{ERR_BAD_INPUT} share_len == 17 || share_len == 25 ||
		share_len == 33.
	\expect{ERR_BAD_INPUT} iter >= 10000.
	\expect{ERR_BAD_INPUT} 1 <= share[0] <= 16.
	\return ERR_OK, если контейнер успешно создан, и код ошибки	в противном
	случае.
	\remark Первый октет частичного секрета определяет его номер.
*/
err_t bpkiESSEnc(
	octet cont[],			/*!< [out] контейнер */
	const octet share[],	/*!< [in] частичный секрет */
	size_t share_len,		/*!< [in] длина частичного секрета */
	const octet pwd[],		/*!< [in] пароль */
	size_t pwd_len,			/*!< [in] длина пароля */
	size_t iter,			/*!< [in] синхропосылка ("соль") */
	const octet salt[8]		/*!< [in] число итераций */
);

/*!	\brief Разбор контейнера с частичным секретом

	Из контейнера [cont_len]cont извлекается частичный секрет [share_len]share,
	где
		share_len = 8 * bpkiESS_keep^{-1}(cont_len) + 1.
	С секрета снимается защита на пароле [pwd_len]pwd. Параметры защиты
	прочитываются из контейнера.
	\expect{ERR_BAD_INPUT} cont_len == bpkiESS_keep(l),	где l == 128 ||
		l == 192 ||	l == 256.
	\return ERR_OK, если контейнер успешно разобран, и код ошибки в противном
	случае.
*/
err_t bpkiESSDec(
	octet share[],			/*!< [out] частичный секрет */
	const octet cont[],		/*!< [in] контейнер */
	size_t cont_len,		/*!< [in] размер контейнера */
	const octet pwd[],		/*!< [in] пароль */
	size_t pwd_len			/*!< [in] длина пароля */
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2_BPKI_H */
