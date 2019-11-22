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

#include "XmsgImAuthUsrAuthInfoQuery.h"

XmsgImAuthUsrAuthInfoQuery::XmsgImAuthUsrAuthInfoQuery()
{

}

void XmsgImAuthUsrAuthInfoQuery::handle(shared_ptr<XmsgNeUsr> nu, SptrXitp trans, shared_ptr<XmsgImAuthUsrAuthInfoQueryReq> req)
{
	shared_ptr<XmsgImAuthTokenColl> token = XmsgImAuthAccountTokenMgr::instance()->find(req->token());
	if (token == nullptr)
	{
		LOG_DEBUG("can not found auth-info for token, req: %s", req->ShortDebugString().c_str())
		trans->endDesc(RET_FORBIDDEN, "can not found auth info for token");
		return;
	}
	shared_ptr<XmsgImAuthUsrAuthInfoQueryRsp> rsp(new XmsgImAuthUsrAuthInfoQueryRsp());
	rsp->set_secret(token->secret);
	rsp->set_gts(token->gts);
	rsp->set_expired(token->expired);
	rsp->mutable_info()->CopyFrom(*token->info);
	trans->end(rsp);
}

XmsgImAuthUsrAuthInfoQuery::~XmsgImAuthUsrAuthInfoQuery()
{

}

