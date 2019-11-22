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
#include "XmsgImAuthSimple.h"

XmsgImAuthSimple::XmsgImAuthSimple()
{

}

void XmsgImAuthSimple::handle(shared_ptr<XscChannel> channel, SptrXitp trans, shared_ptr<XmsgImAuthSimpleReq> req)
{
	if (req->usr().empty() || req->salt().length() < X_MSG_LEN_MIN_SALT || req->sign().empty() || !req->has_dev())
	{
		LOG_DEBUG("request format error, req: %s", req->ShortDebugString().c_str())
		trans->end(RET_FORMAT_ERROR);
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
		LOG_DEBUG("request format error, unsupported plat: %s", req->dev().ShortDebugString().c_str())
		trans->endDesc(RET_FORMAT_ERROR, "unsupported plat: %s", req->dev().plat().c_str());
		return;
	}
	auto account = XmsgImAuthAccountMgr::instance()->findByUsr(req->usr());
	if (account == nullptr)
	{
		LOG_DEBUG("can not found account for usr, req: %s", req->ShortDebugString().c_str())
		trans->end(RET_USR_OR_PASSWORD_ERROR);
		return;
	}
	if (Crypto::sha256ToHexStrLowerCase(req->usr() + req->salt() + account->pwdSha256) != req->sign())
	{
		LOG_DEBUG("sign verify failed, req: %s", req->ShortDebugString().c_str())
		trans->end(RET_USR_OR_PASSWORD_ERROR);
		return;
	}
	shared_ptr<XmsgImAuthTokenColl> token(new XmsgImAuthTokenColl());
	token->token = Crypto::gen0aAkey256();
	token->usr = account->usr;
	token->cgt = account->cgt;
	token->secret = Crypto::gen0aAkey256();
	token->gts = DateMisc::nowGmt0();
	token->expired = token->gts + (XmsgImAuthCfg::instance()->cfgPb->misc().tokenexpiredseconds() * 1000L);
	token->info.reset(new XmsgImClientDeviceInfo());
	token->info->CopyFrom(req->dev());
	XmsgImAuthAccountTokenMgr::instance()->add(token); 
	XmsgImAuthDb::instance()->future([token, req]
	{
		if(!XmsgImAuthTokenCollOper::instance()->insert(token)) 
		{
			LOG_ERROR("insert XmsgImAuthTokenColl to database failed, token: %s, req: %s", token->toString().c_str(), req->ShortDebugString().c_str())
			return;
		}
		LOG_DEBUG("insert XmsgImAuthTokenColl to database successful, token: %s, req: %s", token->toString().c_str(), req->ShortDebugString().c_str())
	});
	shared_ptr<XmsgImAuthSimpleRsp> rsp(new XmsgImAuthSimpleRsp());
	rsp->set_token(token->token);
	rsp->set_secret(Crypto::aes128enc2hexStrLowerCase(Crypto::sha256ToHexStrLowerCase(req->salt() + account->pwdSha256), token->secret));
	rsp->set_expired(token->expired);
	rsp->set_cgt(account->cgt->toString());
	XmsgImClientServiceAddress* apAddr = rsp->add_apaddr();
	int port;
	Net::str2ipAndPort(XmsgImAuthCfg::instance()->cfgPb->misc().xmsgapserviceaddr().c_str(), apAddr->mutable_ip(), &port);
	apAddr->set_port(port);
	apAddr->set_weight(100);
	apAddr->add_proto("tcp");
	XmsgImClientServiceAddress* fsAddr = rsp->add_fsaddr();
	Net::str2ipAndPort(XmsgImAuthCfg::instance()->cfgPb->misc().xmsgossserviceaddr().c_str(), fsAddr->mutable_ip(), &port);
	fsAddr->set_port(port);
	fsAddr->set_weight(100);
	fsAddr->add_proto("http");
	LOG_DEBUG("x-msg-im-usr auth successful, req: %s, rsp: %s", req->ShortDebugString().c_str(), rsp->ShortDebugString().c_str())
	trans->addOob(XSC_TAG_PLATFORM, req->dev().plat());
	trans->end(rsp);
}

XmsgImAuthSimple::~XmsgImAuthSimple()
{

}

