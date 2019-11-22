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

#include <libx-msg-im-auth-db.h>
#include "XmsgImAuthOrgRegiste.h"

XmsgImAuthOrgRegiste::XmsgImAuthOrgRegiste()
{

}

void XmsgImAuthOrgRegiste::handle(shared_ptr<XmsgNeUsr> nu, SptrXitp trans, shared_ptr<XmsgImAuthOrgRegisteReq> req)
{
	string usr;
	if (!XmsgMisc::getStr(req->info(), "usr", usr))
	{
		LOG_ERROR("missing required parameter: usr, req: %s", req->ShortDebugString().c_str())
		trans->endDesc(RET_FORMAT_ERROR, "missing required parameter: usr,");
		return;
	}
	if (!Misc::checkNameFormat(usr, X_MSG_LEN_MIN_USER_NAME, X_MSG_LEN_MAX_USER_NAME))
	{
		trans->endDesc(RET_FORMAT_ERROR, "usr format error: %s", usr.c_str());
		return;
	}
	string pwdSha256;
	if (!XmsgMisc::getStr(req->info(), "pwdSha256", pwdSha256))
	{
		LOG_ERROR("missing required parameter: pwdSha256, req: %s", req->ShortDebugString().c_str())
		trans->endDesc(RET_FORMAT_ERROR, "missing required parameter: pwdSha256");
		return;
	}
	if (pwdSha256.empty() || pwdSha256.length() != 0x40 )
	{
		trans->endDesc(RET_FORMAT_ERROR, "pwdSha256 format error: %s", pwdSha256.c_str());
		return;
	}
	bool localAuth;
	if (!XmsgMisc::getBool(req->info(), "localAuth", localAuth))
	{
		LOG_ERROR("missing required parameter: localAuth, req: %s", req->ShortDebugString().c_str())
		trans->endDesc(RET_FORMAT_ERROR, "missing required parameter: localAuth");
		return;
	}
	bool enable;
	if (!XmsgMisc::getBool(req->info(), "enable", enable))
	{
		LOG_ERROR("missing required parameter: enable, req: %s", req->ShortDebugString().c_str())
		trans->endDesc(RET_FORMAT_ERROR, "missing required parameter: enable");
		return;
	}
	XmsgImAuthDb::instance()->future([nu, trans, req, usr, pwdSha256, enable, localAuth]
	{
		XmsgImAuthOrgRegiste::registe(nu, trans, req, usr, pwdSha256, enable, localAuth);
	});
}

void XmsgImAuthOrgRegiste::registe(shared_ptr<XmsgNeUsr> nu, SptrXitp trans, shared_ptr<XmsgImAuthOrgRegisteReq> req, const string& usr, const string& pwdSha256, bool enable, bool localAuth)
{
	auto account = XmsgImAuthAccountMgr::instance()->findByUsr(usr);
	if (account != nullptr)
	{
		trans->endDesc(RET_FORBIDDEN, "usr already existed: %s", usr.c_str());
		return;
	}
	auto hlr = ChannelGlobalTitle::parse(nu->uid);
	if (hlr == nullptr)
	{
		LOG_FAULT("it`s a bug, x-msg-im-hlr channel gloal title format error: %s", nu->toString().c_str())
		trans->endDesc(RET_EXCEPTION, "system exception");
		return;
	}
	shared_ptr<XmsgImAuthAccountColl> coll(new XmsgImAuthAccountColl());
	coll->usr = usr;
	coll->cgt = ChannelGlobalTitle::genUsr(hlr);
	coll->pwdSha256 = pwdSha256;
	coll->localAuth = localAuth;
	coll->enable = enable;
	coll->info.reset(new XmsgKv());
	*(coll->info->mutable_kv()) = req->info();
	coll->info->mutable_kv()->erase("usr");
	coll->info->mutable_kv()->erase("pwdSha256");
	coll->info->mutable_kv()->erase("enable");
	coll->info->mutable_kv()->erase("localAuth");
	coll->gts = DateMisc::nowGmt0();
	coll->uts = coll->gts;
	if (!XmsgImAuthAccountCollOper::instance()->insert(coll))
	{
		LOG_ERROR("registe x-msg-im account failed, may be database exception, coll: %s", coll->toString().c_str())
		trans->endDesc(RET_EXCEPTION, "registe x-msg-im account failed, may be database exception, req: %s", req->ShortDebugString().c_str());
		return;
	}
	LOG_INFO("registe x-msg-im account successful, coll: %s", coll->toString().c_str())
	shared_ptr<XmsgImAuthOrgRegisteRsp> rsp(new XmsgImAuthOrgRegisteRsp());
	rsp->set_cgt(coll->cgt->toString());
	trans->end(rsp);
	if (!XmsgImAuthAccountMgr::instance()->add(coll))
	{
		LOG_FAULT("it`s a bug, account already existed: %s", coll->toString().c_str())
	}
}

XmsgImAuthOrgRegiste::~XmsgImAuthOrgRegiste()
{

}

