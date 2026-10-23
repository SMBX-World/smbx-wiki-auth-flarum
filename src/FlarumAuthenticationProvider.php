<?php

/*
 * This file is part of the AuthFlarum package.
 *
 * Copyright (C) 2021 Guillaume Kulakowski <guillaume@kulakowski.fr>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace AuthFlarum;

use MediaWiki\Auth\AbstractPasswordPrimaryAuthenticationProvider;
use MediaWiki\Auth\AuthenticationRequest;
use MediaWiki\Auth\AuthenticationResponse;
use MediaWiki\Auth\PasswordAuthenticationRequest;
use MediaWiki\MediaWikiServices;
use MediaWiki\User\UserNameUtils;
use Message;
use StatusValue;
use Wikimedia\Timestamp\ConvertibleTimestamp;

/**
 * The Autentication provider.
 *
 * @see https://www.mediawiki.org/wiki/Manual:SessionManager_and_AuthManager/Updating_tips
 */
class FlarumAuthenticationProvider extends AbstractPasswordPrimaryAuthenticationProvider {
	/**
	 * Flarum user.
	 * @var FlarumUser
	 */
	private FlarumUser $flarumUser;

	/**
	 * Automatically create an account when asked to log in a
	 * Flarum user that does not exist in MediaWiki.
	 *
	 * @return bool
	 */
	public function accountCreationType() {
		return self::TYPE_CREATE;
	}

	/**
	 * Account creation from MediaWiki to flarum
	 *
	 * @param string $user
	 * @param stdObject $creator
	 * @param array $reqs
	 * @return AuthenticationResponse Response of authentication
	 */
	public function beginPrimaryAccountCreation( $user, $creator, array $reqs ) {
		return AuthenticationResponse::newAbstain();
	}

	/**
	 * Handle authentication: return PASS if the given credentials are good in Flarum,
	 * FAIL if they are bad, or ABSTAIN if they cannot be handled by this provider.
	 *
	 * @param array $reqs Query to authenticate
	 * @return AuthenticationResponse Response of authentication
	 */
	public function beginPrimaryAuthentication( array $reqs ) {
		$req = AuthenticationRequest::getRequestByClass( $reqs, PasswordAuthenticationRequest::class );

		if ( !$req || $req->username === null || $req->password === null ) {
			return AuthenticationResponse::newAbstain();
		}

		// 登录标识可能是邮箱，也可能是大小写不同的 Flarum 用户名，
		// 因此必须原样交给 Flarum 验证。
		$this->flarumUser = new FlarumUser( $req->username, $req->password );

		if ( !$this->flarumUser->exists() ) {
			return AuthenticationResponse::newAbstain();
		}

		// 始终使用 Flarum 账号中的用户名作为 MediaWiki 账号名，
		// 而不是登录时输入的标识：否则邮箱和用户名的每种大小写
		// 都会对应到不同的 MediaWiki 账号。
		$userNameUtils = MediaWikiServices::getInstance()->getUserNameUtils();
		$canonicalUsername = $userNameUtils->getCanonical(
			$this->flarumUser->getUsername(),
			UserNameUtils::RIGOR_USABLE
		);
		if ( $canonicalUsername === false ) {
			return AuthenticationResponse::newAbstain();
		}

		return AuthenticationResponse::newPass( $canonicalUsername );
	}

	/**
	 * Allow the password to be changed.
	 *
	 * [providerAllowsAuthenticationDataChange description]
	 * @param AuthenticationRequest $req
	 * @param bool $checkData
	 * @return static
	 */
	public function providerAllowsAuthenticationDataChange( AuthenticationRequest $req, $checkData = true ) {
		return StatusValue::newFatal( new Message( 'authflarum-change-not-allowed' ) );
	}

	/**
	 * Allow to change propoerties.
	 *
	 * @param array $property
	 * @return bool
	 */
	public function providerAllowsPropertyChange( $property ) {
		return false;
	}

	/**
	 * Set a new password for the user.	The corresponding credentials.
	 *
	 * @param AuthenticationRequest $req
	 * @return static
	 */
	public function providerChangeAuthenticationData( AuthenticationRequest $req ) {
		return AuthenticationResponse::newAbstain();
	}

	/**
	 * Return true if user exist in Flarum
	 *
	 * @param string $username
	 * @param string $flags
	 * @return bool
	 */
	public function testUserExists( $username, $flags = User::READ_NORMAL ) {
		return $this->flarumUser->exists();
	}

	/**
	 * MediaWiki auto-creation requires the user to exist in
	 * Flarum. If testUserExists() returns true this should not be
	 * called.
	 *
	 * @param string $user
	 * @param AuthenticationProvider $autocreate
	 * @param array $options
	 * @return static
	 */
	public function testUserForCreation( $user, $autocreate, array $options = [] ) {
		$authFlarumAutoCreate = MediaWikiServices::getInstance()
							->getConfigFactory()
							->makeConfig( 'AuthFlarum' )
							->get( 'AuthFlarumAutoCreate' );
		if ( $autocreate && $authFlarumAutoCreate ) {
			if ( !$this->flarumUser->exists() ) {
				return StatusValue::newFatal( new Message( 'authflarum-autocreate-fail' ) );
			}
			if ( !$this->flarumUser->hasCommentCount() ) {
				return StatusValue::newFatal( new Message( 'authflarum-autocreate-no-enough' ) );
			}

			// Create MW user
			$user->setEmail( $this->flarumUser->getEmail() );
			$user->setRealName( $this->flarumUser->getUsername() );
			$user->setEmailAuthenticationTimestamp( ConvertibleTimestamp::now() );
			$user->saveSettings();
		}

		return StatusValue::newGood();
	}

	/**
	 * Update MediaWiki user from Flarum.
	 *
	 * @param User|null $user
	 * @param AuthenticationResponse $response
	 */
	public function postAuthentication( $user, AuthenticationResponse $response ): void {
		if ( $user && $response->status === AuthenticationResponse::PASS
							 && $this->flarumUser->exists()
							 && $this->flarumUser->isEmailConfirmed()
							 && $response->username == $user->getName() ) {
			$userUpdated = false;

			if ( $user->getEmail() != $this->flarumUser->getEmail() ) {
				$userUpdated = true;
				$user->setEmail( $this->flarumUser->getEmail() );
				$user->setEmailAuthenticationTimestamp( $this->flarumUser->getJoinTime()->getTimestamp() );
			}

			if ( $user->getRealName() != $this->flarumUser->getDisplayName() ) {
				$userUpdated = true;
				$user->setRealName( $this->flarumUser->getDisplayName() );
			}

			if ( $userUpdated ) {
				$user->saveSettings();
			}
		}
	}
}
