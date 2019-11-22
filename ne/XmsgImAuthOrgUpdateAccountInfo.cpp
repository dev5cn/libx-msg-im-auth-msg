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
#include "XmsgImAuthOrgUpdateAccountInfo.h"

XmsgImAuthOrgUpdateAccountInfo::XmsgImAuthOrgUpdateAccountInfo()
{

}

void XmsgImAuthOrgUpdateAccountInfo::handle(shared_ptr<XmsgNeUsr> nu, SptrXitp trans, shared_ptr<XmsgImAuthOrgUpdateAccountInfoReq> req)
{
	if (req->cgt().empty())
	{
		trans->endDesc(RET_FORMAT_ERROR, "channel global title can not be null");
		return;
	}
	string usr;
	if (XmsgMisc::getStr(req->upsert(), "usr", usr))
	{
		if (!Misc::checkNameFormat(usr, X_MSG_LEN_MIN_USER_NAME, X_MSG_LEN_MAX_USER_NAME))
		{
			trans->endDesc(RET_FORMAT_ERROR, "usr format error: %s", usr.c_str());
			return;
		}
	}
	string pwdSha256;
	if (XmsgMisc::getStr(req->upsert(), "pwdSha256", pwdSha256))
	{
		if (pwdSha256.empty() || pwdSha256.length() != 0x40 )
		{
			trans->endDesc(RET_FORMAT_ERROR, "pwdSha256 format error: %s", pwdSha256.c_str());
			return;
		}
	}
	XmsgImAuthDb::instance()->future([trans, req, usr, pwdSha256]
	{
		XmsgImAuthOrgUpdateAccountInfo::update2db(trans, req, usr, pwdSha256);
	});
}

void XmsgImAuthOrgUpdateAccountInfo::update2db(SptrXitp trans, shared_ptr<XmsgImAuthOrgUpdateAccountInfoReq> req, const string& usr, const string& pwdSha256)
{
	auto account = XmsgImAuthAccountMgr::instance()->findByUsr(req->cgt());
	if (account == nullptr)
	{
		trans->endDesc(RET_FORBIDDEN, "can not found usr for channel global title: %s", req->cgt().c_str());
		return;
	}
	account->usr = usr;
	account->pwdSha256 = pwdSha256;
	bool enable;
	if (XmsgMisc::getBool(req->upsert(), "enable", enable))
		account->enable = enable;
	bool localAuth;
	if (XmsgMisc::getBool(req->upsert(), "localAuth", localAuth))
		account->localAuth = localAuth;
	Map<string, string> clone = req->upsert();
	clone.erase("usr");
	clone.erase("pwdSha256");
	clone.erase("enable");
	clone.erase("localAuth");
	shared_ptr<XmsgKv> info(new XmsgKv());
	*(info->mutable_kv()) = account->info->kv();
	XmsgMisc::updateKv(clone, req->remove(), *(info->mutable_kv()));
	account->info = info; 
	if (!XmsgImAuthAccountCollOper::instance()->update(account))
	{
		LOG_ERROR("update user info failed, may be database exception, account: %s", account->toString().c_str())
		trans->endDesc(RET_EXCEPTION, "update user info failed, may be database exception");
		return;
	}
	LOG_INFO("update account info successful, usr: %s", account->toString().c_str())
	shared_ptr<XmsgImAuthOrgUpdateAccountInfoRsp> rsp(new XmsgImAuthOrgUpdateAccountInfoRsp());
	XmsgMisc::insertKv(rsp->mutable_ext(), "ok", "true");
	trans->end(rsp);
}

XmsgImAuthOrgUpdateAccountInfo::~XmsgImAuthOrgUpdateAccountInfo()
{

}

