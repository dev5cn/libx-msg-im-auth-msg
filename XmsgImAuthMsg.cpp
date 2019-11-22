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

#include "XmsgImAuthMsg.h"
#include "mgr/XmsgImMgrNeNetLoad.h"
#include "msg/XmsgImAuthRegSimple.h"
#include "msg/XmsgImAuthSimple.h"
#include "ne/XmsgImAuthClientAttachSimple.h"
#include "ne/XmsgImAuthOrgRegiste.h"
#include "ne/XmsgImAuthOrgUpdateAccountInfo.h"
#include "ne/XmsgImAuthUsrAuthInfoQuery.h"
#include "ne/XmsgNeAuth.h"

XmsgImAuthMsg::XmsgImAuthMsg()
{

}

void XmsgImAuthMsg::init(vector<shared_ptr<XmsgImN2HMsgMgr>> pubMsgMgrs, shared_ptr<XmsgImN2HMsgMgr> priMsgMgr)
{
	for (auto& it : pubMsgMgrs) 
	{
		X_MSG_N2H_PRPC_BEFOR_AUTH(it, XmsgImAuthRegSimpleReq, XmsgImAuthRegSimpleRsp, XmsgImAuthRegSimple::handle)
		X_MSG_N2H_PRPC_BEFOR_AUTH(it, XmsgImAuthSimpleReq, XmsgImAuthSimpleRsp, XmsgImAuthSimple::handle)
	}
	X_MSG_N2H_PRPC_AFTER_AUTH(priMsgMgr, XmsgImAuthClientAttachSimpleReq, XmsgImAuthClientAttachSimpleRsp, XmsgImAuthClientAttachSimple::handle)
	X_MSG_N2H_PRPC_AFTER_AUTH(priMsgMgr, XmsgImAuthOrgRegisteReq, XmsgImAuthOrgRegisteRsp, XmsgImAuthOrgRegiste::handle)
	X_MSG_N2H_PRPC_AFTER_AUTH(priMsgMgr, XmsgImAuthOrgUpdateAccountInfoReq, XmsgImAuthOrgUpdateAccountInfoRsp, XmsgImAuthOrgUpdateAccountInfo::handle)
	X_MSG_N2H_PRPC_AFTER_AUTH(priMsgMgr, XmsgImAuthUsrAuthInfoQueryReq, XmsgImAuthUsrAuthInfoQueryRsp, XmsgImAuthUsrAuthInfoQuery::handle)
	X_MSG_N2H_PRPC_BEFOR_AUTH(priMsgMgr, XmsgNeAuthReq, XmsgNeAuthRsp, XmsgNeAuth::handle)
	X_MSG_N2H_PRPC_AFTER_AUTH(priMsgMgr, XmsgImMgrNeNetLoadReq, XmsgImMgrNeNetLoadRsp, XmsgImMgrNeNetLoad::handle)
}

XmsgImAuthMsg::~XmsgImAuthMsg()
{

}

