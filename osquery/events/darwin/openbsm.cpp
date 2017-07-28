#include <bsm/libbsm.h>

#include <bsm/audit.h>
#include <osquery/flags.h>
#include <osquery/logger.h>

#include "openbsm.h"

namespace osquery {

/// The OpenBSM subsystem may have a performance impact on the system.
FLAG(bool,
     disable_openbsm,
     true,
     "Disable receiving events from the audit subsystem");

REGISTER(OpenBSMEventPublisher, "event_publisher", "openbsm_events");

Status OpenBSMEventPublisher::setUp() {
	if (FLAGS_disable_openbsm) {
    	return Status(1, "Publisher disabled via configuration");
  	}
  	audit_pipe = fopen ("/dev/auditpipe" , "r");
  	if (audit_pipe == nullptr) {
  		LOG(WARNING) << "The auditpipe couldn't be opened.";
  		return Status(1, "Could not open OpenBSM pipe");
  	}
  	VLOG(1) << "OpenBSM is starting";
	return Status(0);
}
void OpenBSMEventPublisher::configure() {}
void OpenBSMEventPublisher::tearDown() {
	fclose(audit_pipe);
}
Status OpenBSMEventPublisher::run() {
	if (audit_pipe == nullptr) {
		return Status(1, "No open audit_pipe");
	}
	unsigned char *buffer;
	std::string del = ",";
	tokenstr_t tok;
	auto reclen = 0;
   	auto bytesread = 0;

	while((reclen = au_read_rec(audit_pipe, &buffer)) != -1) {
		bytesread = 0;
		BSMRecord rec;
		while (bytesread < reclen) {
			if(au_fetch_tok(&tok, buffer + bytesread, reclen - bytesread) == -1) {
				break;
			}
			// This can be used to parse the log for us and provided in a delimited list or XML
			// It only writes to file descriptors though. fopenmem()?
			// au_print_flags_tok(stdout, &tok, &del[0], AU_OFLAG_XML);
			switch (tok.id) {
				case AUT_HEADER32:
					rec.event_id = tok.tt.hdr32_ex.e_type;
					rec.time = tok.tt.hdr32.s;
					break;
				case AUT_HEADER32_EX:
					rec.event_id = tok.tt.hdr32_ex.e_type;
					rec.time = tok.tt.hdr32_ex.s;
					break;
				case AUT_HEADER64:
					rec.event_id = tok.tt.hdr64.e_type;
					rec.time = tok.tt.hdr64_ex.s;
					break;
				case AUT_HEADER64_EX:
					rec.event_id = tok.tt.hdr32_ex.e_type;
					rec.time = tok.tt.hdr64_ex.s;
					break;
				case AUT_SUBJECT32:
					rec.pid = tok.tt.subj32.pid;
					rec.euid = tok.tt.subj32.euid;
					rec.egid = tok.tt.subj32.egid;
					rec.ruid = tok.tt.subj32.ruid;
					rec.rgid = tok.tt.subj32.rgid;
					break;
				case AUT_SUBJECT64:
					rec.pid = tok.tt.subj64.pid;
					rec.euid = tok.tt.subj64.euid;
					rec.egid = tok.tt.subj64.egid;
					rec.ruid = tok.tt.subj64.ruid;
					rec.rgid = tok.tt.subj64.rgid;
					break;
				case AUT_SUBJECT32_EX:
					rec.pid = tok.tt.subj32_ex.pid;
					rec.euid = tok.tt.subj32_ex.euid;
					rec.egid = tok.tt.subj32_ex.egid;
					rec.ruid = tok.tt.subj32_ex.ruid;
					rec.rgid = tok.tt.subj32_ex.rgid;
					break;
				case AUT_RETURN32:
					rec.status = (u_int64_t)tok.tt.ret32.status;
					break;
				case AUT_RETURN64:
					rec.status = tok.tt.ret64.err;
					break;
				case AUT_EXEC_ARGS:
					for (unsigned int i = 0; i < tok.tt.execarg.count; ++i) {
						rec.args.push_back(tok.tt.execarg.text[i]);
					}
				break;
				case AUT_ATTR:
				case AUT_ATTR32:
					rec.dev = tok.tt.attr32.fsid;
					rec.inode = tok.tt.attr32.nid;
					break;
				case AUT_PATH:
					rec.path = tok.tt.path.path;
					break;
			}
			bytesread += tok.len;
		}
		// This buffer comes from au_read_rec and we need to free it
		free(buffer);
		auto ec = createEventContext();
  		ec->event_id = rec.event_id;
  		ec->event_details = rec.toMap();
  		fire(ec);
  		if (isEnding()) {
			return Status(0);
		}
	}
	return Status(0);
}

bool OpenBSMEventPublisher::shouldFire(const OpenBSMSubscriptionContextRef& mc,
                  					   const OpenBSMEventContextRef& ec) const {
	if (mc->event_id ==  ec->event_id) {
		return true;
	}
	return false;
}
}