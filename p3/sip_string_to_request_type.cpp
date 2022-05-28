#include <atomic>
#include <string.h>
#include "snmp_sip_request_types.h"

namespace SNMP
{
SIPRequestTypes string_to_request_type(char* req_string, int slen )
{
  if (!strncmp(req_string, "INVITE", slen)) { return SIPRequestTypes::INVITE; }
  else if (!strncmp(req_string, "ACK", slen)) { return SIPRequestTypes::ACK; }
  else if (!strncmp(req_string, "BYE", slen)) { return SIPRequestTypes::BYE; }
  else if (!strncmp(req_string, "CANCEL", slen)) { return SIPRequestTypes::CANCEL; }
  else if (!strncmp(req_string, "OPTIONS", slen)) { return SIPRequestTypes::OPTIONS; }
  else if (!strncmp(req_string, "REGISTER", slen)) { return SIPRequestTypes::REGISTER; }
  else if (!strncmp(req_string, "PRACK", slen)) { return SIPRequestTypes::PRACK; }
  else if (!strncmp(req_string, "SUBSCRIBE", slen)) { return SIPRequestTypes::SUBSCRIBE; }
  else if (!strncmp(req_string, "NOTIFY", slen)) { return SIPRequestTypes::NOTIFY; }
  else if (!strncmp(req_string, "PUBLISH", slen)) { return SIPRequestTypes::PUBLISH; }
  else if (!strncmp(req_string, "INFO", slen)) { return SIPRequestTypes::INFO; }
  else if (!strncmp(req_string, "REFER", slen)) { return SIPRequestTypes::REFER; }
  else if (!strncmp(req_string, "MESSAGE", slen)) { return SIPRequestTypes::MESSAGE; }
  else if (!strncmp(req_string, "UPDATE", slen)) { return SIPRequestTypes::UPDATE; }
  else { return SIPRequestTypes::OTHER; }
}
}
