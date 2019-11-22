/*
  Copyright 2019 www.dev5.cn, Inc. dev5@qq.com
 
  This file is part of X-MSG-IM.
 
  X-MSG-IM is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  X-MSG-IM is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
 
  You should have received a copy of the GNU Affero General Public License
  along with X-MSG-IM.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "XmsgImAuthClientAttachSimple.h"

XmsgImAuthClientAttachSimple::XmsgImAuthClientAttachSimple()
{

}

void XmsgImAuthClientAttachSimple::handle(shared_ptr<XmsgNeUsr> nu, SptrXitp trans, shared_ptr<XmsgImAuthClientAttachSimpleReq> req)
{
	shared_ptr<XmsgImAuthTokenColl> token = XmsgImAuthAccountTokenMgr::instance()->find(req->token());
	if (token == nullptr)
	{
		LOG_DEBUG("can not found auth-info for token, req: %s", req->ShortDebugString().c_str())
		trans->endDesc(RET_FORBIDDEN, "can not found auth info for token");
		return;
	}
	shared_ptr<XmsgImAuthAccountColl> account = XmsgImAuthAccountMgr::instance()->findByUsr(token->usr);
	if (account == nullptr)
	{
		LOG_ERROR("can not found account for token, req: %s", req->ShortDebugString().c_str());
		trans->endDesc(RET_FORBIDDEN, "can not found account for usr");
		return;
	}
	shared_ptr<XmsgImAuthClientAttachSimpleRsp> rsp(new XmsgImAuthClientAttachSimpleRsp());
	rsp->set_usr(account->usr);
	rsp->set_secret(token->secret);
	rsp->set_gts(token->gts);
	rsp->set_expired(token->expired);
	rsp->mutable_info()->CopyFrom(*token->info);
	LOG_DEBUG("have a x-msg-im-client attach successful, req: %s, rsp: %s", req->ShortDebugString().c_str(), rsp->ShortDebugString().c_str())
	trans->end(rsp);
}

XmsgImAuthClientAttachSimple::~XmsgImAuthClientAttachSimple()
{

}

