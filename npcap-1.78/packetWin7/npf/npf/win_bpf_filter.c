/***********************IMPORTANT NPCAP LICENSE TERMS***********************
 *
 * Npcap (https://npcap.com) is a Windows packet sniffing driver and library and
 * is copyright (c) 2013-2023 by Nmap Software LLC ("The Nmap Project").  All
 * rights reserved.
 *
 * Even though Npcap source code is publicly available for review, it is not
 * open source software and may not be redistributed or used in other software
 * without special permission from the Nmap Project. The standard (free) version
 * is usually limited to installation on five systems. For more details, see the
 * LICENSE file included with Npcap and also available at
 * https://github.com/nmap/npcap/blob/master/LICENSE. This header file
 * summarizes a few important aspects of the Npcap license, but is not a
 * substitute for that full Npcap license agreement.
 *
 * We fund the Npcap project by selling two types of commercial licenses to a
 * special Npcap OEM edition:
 *
 * 1) The Npcap OEM Redistribution License allows companies distribute Npcap OEM
 * within their products. Licensees generally use the Npcap OEM silent
 * installer, ensuring a seamless experience for end users. Licensees may choose
 * between a perpetual unlimited license or a quarterly term license, along with
 * options for commercial support and updates. Prices and details:
 * https://npcap.com/oem/redist.html
 *
 * 2) The Npcap OEM Internal-Use License is for organizations that wish to use
 * Npcap OEM internally, without redistribution outside their organization. This
 * allows them to bypass the 5-system usage cap of the Npcap free edition. It
 * includes commercial support and update options, and provides the extra Npcap
 * OEM features such as the silent installer for automated deployment. Prices
 * and details: https://npcap.com/oem/internal.html
 *
 * Both of these licenses include updates and support as well as a warranty.
 * Npcap OEM also includes a silent installer for unattended installation.
 * Further details about Npcap OEM are available from https://npcap.com/oem/,
 * and you are also welcome to contact us at sales@nmap.com to ask any questions
 * or set up a license for your organization.
 *
 * Free and open source software producers are also welcome to contact us for
 * redistribution requests. However, we normally recommend that such authors
 * instead ask your users to download and install Npcap themselves. It will be
 * free for them if they need 5 or fewer copies.
 *
 * If the Nmap Project (directly or through one of our commercial licensing
 * customers) has granted you additional rights to Npcap or Npcap OEM, those
 * additional rights take precedence where they conflict with the terms of the
 * license agreement.
 *
 * Since the Npcap source code is available for download and review, users
 * sometimes contribute code patches to fix bugs or add new features. By sending
 * these changes to the Nmap Project (including through direct email or our
 * mailing lists or submitting pull requests through our source code
 * repository), it is understood unless you specify otherwise that you are
 * offering the Nmap Project the unlimited, non-exclusive right to reuse,
 * modify, and relicense your code contribution so that we may (but are not
 * obligated to) incorporate it into Npcap. If you wish to specify special
 * license conditions or restrictions on your contributions, just say so when
 * you send them.
 *
 * This software is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. Warranty rights and commercial support are
 * available for the OEM Edition described above.
 *
 * Other copyright notices and attribution may appear below this license header.
 * We have kept those for attribution purposes, but any license terms granted by
 * those notices apply only to their original work, and not to any changes made
 * by the Nmap Project or to this entire file.
 *
 ***************************************************************************/
/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2007 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies 
 * nor the names of its contributors may be used to endorse or promote 
 * products derived from this software without specific prior written 
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "stdafx.h"

#include <ndis.h>
#include <limits.h>

#ifndef UNUSED
#define UNUSED(_x) (_x)
#endif

#include "win_bpf.h"

#include "valid_insns.h"

#define EXTRACT_SHORT(p)\
		((((u_short)(((u_char*)p)[0])) << 8) |\
		 (((u_short)(((u_char*)p)[1])) << 0))

#define EXTRACT_LONG(p)\
		((((u_int32)(((u_char*)p)[0])) << 24) |\
		 (((u_int32)(((u_char*)p)[1])) << 16) |\
		 (((u_int32)(((u_char*)p)[2])) << 8 ) |\
		 (((u_int32)(((u_char*)p)[3])) << 0 ))

#define MDLIDX(len, p, k, buf) \
{ \
	NdisQueryMdl(p, &buf, &len, NormalPagePriority); \
	if (buf == NULL) \
		return 0; \
	while (k >= len) { \
		k -= len; \
		p = p->Next; \
		if (p == NULL) \
			return 0; \
		NdisQueryMdl(p, &buf, &len, NormalPagePriority); \
		if (buf == NULL) \
			return 0; \
	} \
}

u_int32 xword(PMDL p, u_int32 k, int *err)
{
	u_int32 len, len0;
	u_char *CurBuf, *NextBuf;
	PMDL p0;

	*err = 1;
	MDLIDX(len, p, k, CurBuf);
	CurBuf += k;
	if (len - k >= 4) {
		*err = 0;
		return EXTRACT_LONG(CurBuf);
	}
	p0 = p->Next;
	if (p0 == NULL)
		return 0;
	NdisQueryMdl(p0, &NextBuf, &len0, NormalPagePriority);
	if (NextBuf == NULL || (len - k) + len0 < 4)
		return 0;
	*err = 0;

	switch (len - k) {
	case 1:
		return (CurBuf[0] << 24) | (NextBuf[0] << 16) | (NextBuf[1] << 8) | NextBuf[2];
	case 2:
		return (CurBuf[0] << 24) | (CurBuf[1] << 16) | (NextBuf[0] << 8) | NextBuf[1];
	default:
		return (CurBuf[0] << 24) | (CurBuf[1] << 16) | (CurBuf[2] << 8) | NextBuf[0];
	}
}

u_int32 xhalf(PMDL p, u_int32 k, int *err)
{
	u_int32 len, len0;
	u_char *CurBuf, *NextBuf;
	PMDL p0;

	*err = 1;
	MDLIDX(len, p, k, CurBuf);
	CurBuf += k;
	if (len - k >= 2) {
		*err = 0;
		return EXTRACT_SHORT(CurBuf);
	}
	p0 = p->Next;
	if (p0 == NULL)
		return 0;
	NdisQueryMdl(p0, &NextBuf, &len0, NormalPagePriority);
	if (NextBuf == NULL || len0 < 1)
		return 0;
	*err = 0;

	return (CurBuf[0] << 8) | NextBuf[0];
}

u_int32 xbyte(PMDL p, u_int32 k, int *err)
{
	u_int32 len;
	u_char *CurBuf;

	*err = 1;
	MDLIDX(len, p, k, CurBuf);
	*err = 0;

	return CurBuf[k];
}

_Use_decl_annotations_
u_int bpf_filter(const struct bpf_insn *pc, const PMDL p, u_int data_offset, u_int wirelen)
{
	register u_int32 A, X;
	register bpf_u_int32 k;

	int merr = 0;
	int mem[BPF_MEMWORDS];

	RtlZeroMemory(mem, sizeof(mem));

	if (pc == NULL)
	/*
	* No filter means accept all.
	*/
		return (u_int) - 1;
	A = 0;
	X = 0;
	--pc;
	while (1)
	{
		++pc;
		switch (pc->code)
		{
		default:
			return 0;

		case BPF_RET|BPF_K:
			return (u_int)pc->k;

		case BPF_RET|BPF_A:
			return (u_int)A;

		case BPF_LD|BPF_W|BPF_ABS:
			k = pc->k;
			A = xword(p, k + data_offset, &merr);
			if (merr != 0) {
				return 0;
			}
			continue;

		case BPF_LD|BPF_H|BPF_ABS:
			k = pc->k;
			A = xhalf(p, k + data_offset, &merr);
			if (merr != 0) {
				return 0;
			}
			continue;

		case BPF_LD|BPF_B|BPF_ABS:
			k = pc->k;
			A = xbyte(p, k + data_offset, &merr);
			if (merr != 0) {
				return 0;
			}
			continue;

		case BPF_LD|BPF_W|BPF_LEN:
			A = wirelen;
			continue;

		case BPF_LDX|BPF_W|BPF_LEN:
			X = wirelen;
			continue;

		case BPF_LD|BPF_W|BPF_IND:
			k = X + pc->k;
			A = xword(p, k + data_offset, &merr);
			if (merr != 0) {
				return 0;
			}
			continue;

		case BPF_LD|BPF_H|BPF_IND:
			k = X + pc->k;
			A = xhalf(p, k + data_offset, &merr);
			if (merr != 0) {
				return 0;
			}
			continue;

		case BPF_LD|BPF_B|BPF_IND:
			k = X + pc->k;
			A = xbyte(p, k + data_offset, &merr);
			if (merr != 0) {
				return 0;
			}
			continue;

		case BPF_LDX|BPF_MSH|BPF_B:
			k = pc->k;
			X = xbyte(p, k + data_offset, &merr);
			if (merr != 0) {
				return 0;
			}
			X = (X & 0xf) << 2;
			continue;

		case BPF_LD|BPF_IMM:
			A = pc->k;
			continue;

		case BPF_LDX|BPF_IMM:
			X = pc->k;
			continue;

		case BPF_LD|BPF_MEM:
			A = mem[pc->k];
			continue;

		case BPF_LDX|BPF_MEM:
			X = mem[pc->k];
			continue;

		case BPF_ST:
			mem[pc->k] = A;
			continue;

		case BPF_STX:
			mem[pc->k] = X;
			continue;

		case BPF_JMP|BPF_JA:
			pc += pc->k;
			continue;

		case BPF_JMP|BPF_JGT|BPF_K:
			pc += ((int)A > (int)pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JGE|BPF_K:
			pc += ((int)A >= (int)pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JEQ|BPF_K:
			pc += ((int)A == (int)pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JSET|BPF_K:
			pc += (A & pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JGT|BPF_X:
			pc += (A > X) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JGE|BPF_X:
			pc += (A >= X) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JEQ|BPF_X:
			pc += (A == X) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JSET|BPF_X:
			pc += (A & X) ? pc->jt : pc->jf;
			continue;

		case BPF_ALU|BPF_ADD|BPF_X:
			A += X;
			continue;

		case BPF_ALU|BPF_SUB|BPF_X:
			A -= X;
			continue;

		case BPF_ALU|BPF_MUL|BPF_X:
			A *= X;
			continue;

		case BPF_ALU|BPF_DIV|BPF_X:
			if (X == 0)
				return 0;
			A /= X;
			continue;

		case BPF_ALU|BPF_AND|BPF_X:
			A &= X;
			continue;

		case BPF_ALU|BPF_OR|BPF_X:
			A |= X;
			continue;

		case BPF_ALU|BPF_LSH|BPF_X:
			A <<= X;
			continue;

		case BPF_ALU|BPF_RSH|BPF_X:
			A >>= X;
			continue;

		case BPF_ALU|BPF_ADD|BPF_K:
			A += pc->k;
			continue;

		case BPF_ALU|BPF_SUB|BPF_K:
			A -= pc->k;
			continue;

		case BPF_ALU|BPF_MUL|BPF_K:
			A *= pc->k;
			continue;

		case BPF_ALU|BPF_DIV|BPF_K:
			A /= pc->k;
			continue;

		case BPF_ALU|BPF_AND|BPF_K:
			A &= pc->k;
			continue;

		case BPF_ALU|BPF_OR|BPF_K:
			A |= pc->k;
			continue;

		case BPF_ALU|BPF_LSH|BPF_K:
			A <<= pc->k;
			continue;

		case BPF_ALU|BPF_RSH|BPF_K:
			A >>= pc->k;
			continue;

		case BPF_ALU|BPF_NEG:
			(int)A = -((int)A);
			continue;

		case BPF_MISC|BPF_TAX:
			X = A;
			continue;

		case BPF_MISC|BPF_TXA:
			A = X;
			continue;
		}
	}
}

//-------------------------------------------------------------------

_Use_decl_annotations_
int bpf_validate(struct bpf_insn * f, int len)
{
	register u_int32 i, from;
	register int j;
	register struct bpf_insn* p;
	int flag;

	INFO_DBG("Validating program\n");

	if (len < 1)
		return 0;

	for (i = 0; i < (u_int32)len; ++i)
	{
		p = &f[i];

		flag = 0;
		for (j = 0; j < VALID_INSTRUCTIONS_LEN; j++)
		{
			if (p->code == valid_instructions[j])
			{
				flag = 1;
				break;
			}
		}
		if (flag == 0)
			return 0;

		INFO_DBG("Validating program: no unknown instructions\n");

		switch (BPF_CLASS(p->code))
		{
			/*
										 * Check that memory operations use valid addresses.
										 */
		case BPF_LD:
		case BPF_LDX:
			switch (BPF_MODE(p->code))
			{
			case BPF_IMM:
				break;
			case BPF_ABS:
			case BPF_IND:
			case BPF_MSH:
				break;
			case BPF_MEM:
				if (p->k >= BPF_MEMWORDS)
					return 0;
				break;
			case BPF_LEN:
				break;
			default:
				return 0;
			}

			INFO_DBG("Validating program: no wrong LD memory locations\n");
			break;

		case BPF_ST:
		case BPF_STX:
			if (p->k >= BPF_MEMWORDS)
				return 0;

			INFO_DBG("Validating program: no wrong ST memory locations\n");
			break;

		case BPF_ALU:
			switch (BPF_OP(p->code))
			{
			case BPF_ADD:
			case BPF_SUB:
			case BPF_MUL:
			case BPF_OR:
			case BPF_AND:
			case BPF_LSH:
			case BPF_RSH:
			case BPF_NEG:
				break;
			case BPF_DIV:
				/*
								 * Check for constant division by 0.
								 */
				if (BPF_SRC(p->code) == BPF_K && p->k == 0)
					return 0;
				break;
			default:
				return 0;
			}
			break;
		case BPF_JMP:
			from = i + 1;
			/*
			 * Check that jumps are within the code block,
			 * and that unconditional branches don't go
			 * backwards as a result of an overflow.
			 * Unconditional branches have a 32-bit offset,
			 * so they could overflow; we check to make
			 * sure they don't.  Conditional branches have
			 * an 8-bit offset, and the from address is <=
			 * BPF_MAXINSNS, and we assume that BPF_MAXINSNS
			 * is sufficiently small that adding 255 to it
			 * won't overflow.
			 *
			 * We know that len is <= BPF_MAXINSNS, and we
			 * assume that BPF_MAXINSNS is < the maximum size
			 * of a u_int, so that i + 1 doesn't overflow.
			 */
			/* Never assume; check instead. */
			C_ASSERT(BPF_MAXINSNS < UINT_MAX - UCHAR_MAX);
			switch (BPF_OP(p->code))
			{
			case BPF_JA:
				if (from + p->k < from || from + p->k >= (u_int32)len)
					return 0;
				break;
			case BPF_JEQ:
			case BPF_JGT:
			case BPF_JGE:
			case BPF_JSET:
				if (from + p->jt >= (u_int32)len || from + p->jf >= (u_int32)len)
					return 0;
				break;
			default:
				return 0;
			}
			INFO_DBG("Validating program: no wrong JUMPS\n");
			break;
		case BPF_RET:
			break;
		case BPF_MISC:
			break;
		default:
			return 0;
		}
	}
	return BPF_CLASS(f[len - 1].code) == BPF_RET;
}
