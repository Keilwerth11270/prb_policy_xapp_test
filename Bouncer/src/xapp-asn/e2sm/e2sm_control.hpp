/*
# ==================================================================================
# Copyright (c) 2020 HCL Technologies Limited.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ==================================================================================
*/


/* Classes to handle E2 service model based on Bouncer-v001.asn */
#ifndef SRC_XAPP_ASN_E2SM_E2SM_CONTROL_HPP_
#define SRC_XAPP_ASN_E2SM_E2SM_CONTROL_HPP_

extern "C" {
  #include <OCTET_STRING.h>
  #include <E2SM-RC-ControlHeader.h>
  #include <E2SM-RC-ControlMessage.h>
  #include <E2SM-RC-CallProcessID.h>
  #include <E2SM-RC-ControlHeader-Format1.h>
  #include <E2SM-RC-ControlMessage-Format1.h>
}

#include <sstream>
#include <e2sm_helpers.hpp>
#include <mdclog/mdclog.h>
#include <vector>

class e2sm_control {
public:
	e2sm_control(void);
  ~e2sm_control(void);

  bool encode_rc_control_header(unsigned char *buf, ssize_t *size, e2sm_rc_control_action_PR action);
  bool encode_rc_control_message(unsigned char *buf, ssize_t *size, e2sm_rc_control_helper *helper);

  std::string  get_error (void) const {return error_string ;};

private:
  E2SM_RC_ControlHeader_Format1_t *generate_e2sm_ue_admission_control_header();
  E2SM_RC_ControlHeader_Format1_t *generate_e2sm_slice_level_prb_quota_header();
  E2SM_RC_ControlMessage_Format1_t *generate_e2sm_ue_admission_control_msg();
  E2SM_RC_ControlMessage_Format1_t *generate_e2sm_slice_level_prb_quota_msg(e2sm_rc_slice_level_prb_quota_helper *helper);
  OCTET_STRING_t *generate_and_encode_nr_cgi(const char *plmnid, unsigned long nr_cell_id);
  void generate_e2sm_rc_ueid(UEID_t *ueid);

  bool set_fields(E2SM_RC_ControlHeader_t *control_header, e2sm_rc_control_action_PR action);
  bool set_fields(E2SM_RC_ControlMessage_t *control_msg);
  bool set_fields(E2SM_RC_ControlMessage_t *control_msg, e2sm_rc_slice_level_prb_quota_helper *helper);

  E2SM_RC_ControlHeader_t *rc_control_header;
  E2SM_RC_ControlMessage_t *rc_control_msg;
  E2SM_RC_CallProcessID_t *rc_call_proc_id;

  size_t errbuf_len;
  char errbuf[128];
  std::string error_string;
};



#endif /* SRC_XAPP_ASN_E2SM_E2SM_CONTROL_HPP_ */
