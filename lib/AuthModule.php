<?php
/**
 * @author Project Seminar "sciebo@Learnweb" of the University of Muenster
 * @copyright Copyright (c) 2017, University of Muenster
 * @license AGPL-3.0
 *
 * This code is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License, version 3,
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

namespace OCA\OAuth2;

use OCA\OAuth2\AppInfo\Application;
use OCA\OAuth2\Db\AccessToken;
use OCA\OAuth2\Db\AccessTokenMapper;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Db\MultipleObjectsReturnedException;
use OCP\Authentication\IAuthModule;
use OCP\IRequest;
use OCP\IUser;
use OCP\IUserManager;

class AuthModule implements IAuthModule {

	/**
	 * Authenticates a request.
	 *
	 * @param IRequest $request The request.
	 *
	 * @return null|IUser The user if the request is authenticated, null otherwise.
	 * @throws \Exception
	 */
	public function auth(IRequest $request) {
		$authHeader = $request->getHeader('Authorization');

		if (strpos($authHeader, 'Bearer ') === false) {
			\OC::$server->getLogger()->debug('No Authorization: Bearer header detected', ['app' => 'oauth2']);
			return null;
		}

		$bearerToken = substr($authHeader, 7);

		$user = $this->authToken($bearerToken);
		if ($user === null) {
			throw new \Exception('Invalid token');
		}
		return $user;
	}

	/**
	 * Returns null because the user's password is not handled in the app.
	 * Triggers a \OC\Authentication\Exceptions\PasswordlessTokenException when
	 * verifying the session, @see \OC\User\Session::checkTokenCredentials().
	 *
	 * Note: This means that only master key encryption is working with the app.
	 *
	 * @param IRequest $request The request.
	 *
	 * @return null
	 */
	public function getUserPassword(IRequest $request) {
		return null;
	}

	/**
	 * @param string $bearerToken
	 * @return null|IUser
	 */
	public function authToken($bearerToken) {
		$app = new Application();
		$container = $app->getContainer();

		/** @var AccessTokenMapper $accessTokenMapper */
		$accessTokenMapper = $container->query(AccessTokenMapper::class);

		try {
			/** @var AccessToken $accessToken */
			$accessToken = $accessTokenMapper->findByToken($bearerToken);

			if ($accessToken->hasExpired()) {
				\OC::$server->getLogger()->debug("token expired $bearerToken", ['app'=>__CLASS__]);
				return null;
			}
		} catch (DoesNotExistException $exception) {
			\OC::$server->getLogger()->debug("token does not exist $bearerToken", ['app'=>__CLASS__]);
			return null;
		} catch (MultipleObjectsReturnedException $e) {
			\OC::$server->getLogger()->debug("multiple tokens exist for $bearerToken", ['app'=>__CLASS__]);
			return null;
		}

		/** @var IUserManager $userManager */
		$userManager = $container->query('UserManager');
		return $userManager->get($accessToken->getUserId());
	}

}
