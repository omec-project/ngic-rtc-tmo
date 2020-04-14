/*
 * Copyright (c) 2020 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _COMMANDS_H_
#define _COMMANDS_H_
/**
 * @file
 * This file contains CLI data objects & prototype.
 */
uint8_t sesstats_flg, rfrsh_sstats, sesstat_idx;
uint8_t pktstats_flg, rfrsh_pstats;
uint8_t trfstats_flg, rfrsh_dstats;
uint8_t mbfstats_flg, rfrsh_mstats;
struct cmdline *ngicdp_cl;
extern cmdline_parse_ctx_t main_ctx[];

enum sess_tblIdx {
	TOP,
	MIDDLE,
	END
};

#endif /* _COMMANDS_H_ */
