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

#ifndef _CP_COMMANDS_H_
#define _CP_COMMANDS_H_
/**
 * @file
 * This file contains CLI data objects & prototype for the CP.
 */

#define QUERY_SZ 32

uint8_t queryimsi_flg;
uint8_t sesstats_flg, sesstat_idx;
uint8_t msgstats_flg, ifistats_flg;
uint8_t rfrsh_istats;
struct cmdline *ngiccp_cl;
extern cmdline_parse_ctx_t main_ctx[];

enum sess_tblIdx {
	TOP,
	MIDDLE,
	END
};

#endif /* _CP_COMMANDS_H_ */
