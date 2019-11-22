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
#include "XmsgImAuthRegSimple.h"

XmsgImAuthRegSimple::XmsgImAuthRegSimple()
{

}

void XmsgImAuthRegSimple::handle(shared_ptr<XscChannel> channel, SptrXitp trans, shared_ptr<XmsgImAuthRegSimpleReq> req)
{
	if (!XmsgImAuthCfg::instance()->cfgPb->misc().registeenable()) 
	{
		trans->endDesc(RET_FORBIDDEN, "registe function disabled");
		return;
	}
	if (req->usr().empty() || req->salt().length() < X_MSG_LEN_MIN_SALT || req->pwd().empty() || (req->pwd().length() % 2) != 0 || !req->has_dev())
	{
		LOG_DEBUG("request format error, req: %s", req->ShortDebugString().c_str())
		trans->end(RET_FORMAT_ERROR);
		return;
	}
	string pwd = Crypto::aes128dec(req->salt(), Net::hexStr2bytes(req->pwd().c_str(), req->pwd().length()));
	if (pwd.empty() || pwd.length() != 0x40 )
	{
		LOG_DEBUG("request format error, req: %s", req->ShortDebugString().c_str())
		trans->endDesc(RET_FORMAT_ERROR, "can not decipher password");
		return;
	}
	if (req->dev().plat().empty() || req->dev().did().empty() || req->dev().ver().empty())
	{
		LOG_DEBUG("request format error, req: %s", req->dev().ShortDebugString().c_str())
		trans->end(RET_FORMAT_ERROR);
		return;
	}
	if (!XmsgMisc::checkPlat(req->dev().plat()))
	{
		LOG_DEBUG("request format error, req: %s", req->dev().ShortDebugString().c_str())
		trans->endDesc(RET_FORMAT_ERROR, "unsupported plat: %s", req->dev().plat().c_str());
		return;
	}
	auto hlr = XmsgNeMgr::instance()->getHlr();
	if (hlr == nullptr)
	{
		LOG_ERROR("can not allocate x-msg-im-hlr, req: %s", req->ShortDebugString().c_str())
		trans->endAndLazyClose(RET_EXCEPTION, "system exception");
		return;
	}
	auto cgt = ChannelGlobalTitle::parse(hlr->uid);
	if (cgt == NULL)
	{
		LOG_FAULT("it`s a bug, x-msg-im-hlr channel gloal title format error: %s, req: %s", hlr->toString().c_str(), req->ShortDebugString().c_str())
		trans->endDesc(RET_EXCEPTION, "system exception");
		return;
	}
	auto account4usr = XmsgImAuthAccountMgr::instance()->findByUsr(req->usr());
	if (account4usr != nullptr)
	{
		LOG_DEBUG("account already existed, req: %s", req->dev().ShortDebugString().c_str())
		trans->endDesc(RET_FORBIDDEN, "account already existed");
		return;
	}
	shared_ptr<XmsgImAuthAccountColl> account(new XmsgImAuthAccountColl());
	account->usr = req->usr(); 
	account->cgt = ChannelGlobalTitle::genUsr(cgt);
	account->pwdSha256 = pwd; 
	account->localAuth = true;
	account->enable = true;
	account->info.reset(new XmsgKv());
	account->gts = DateMisc::nowGmt0();
	account->uts = account->gts;
	if (!XmsgImAuthAccountMgr::instance()->add(account)) 
	{
		LOG_DEBUG("account already existed, req: %s", req->dev().ShortDebugString().c_str())
		trans->endDesc(RET_FORBIDDEN, "account already existed");
		return;
	}
	XmsgImAuthDb::instance()->future([account, req, trans]
	{
		if (!XmsgImAuthAccountCollOper::instance()->insert(account)) 
		{
			LOG_ERROR("save XmsgImAuthAccountColl to database failed, account: %s, req: %s", account->toString().c_str(), req->ShortDebugString().c_str())
			trans->endDesc(RET_EXCEPTION, "may be account already existed");
			return;
		}
		LOG_DEBUG("save XmsgImAuthAccountColl to database successful, account: %s, req: %s", account->toString().c_str(), req->ShortDebugString().c_str())
		shared_ptr<XmsgImAuthRegSimpleRsp> rsp(new XmsgImAuthRegSimpleRsp());
		rsp->set_cgt(account->cgt->toString());
		trans->addOob(XSC_TAG_PLATFORM, req->dev().plat());
		trans->end(rsp);
	});
}

XmsgImAuthRegSimple::~XmsgImAuthRegSimple()
{

}

