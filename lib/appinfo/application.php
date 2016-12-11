<?php
/**
 * @author Lukas Biermann
 * @author Nina Herrmann
 * @author Wladislaw Iwanzow
 * @author Dennis Meis
 * @author Jonathan Neugebauer
 *
 * @copyright Copyright (c) 2016, Project Seminar "PSSL16" at the University of Muenster.
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

namespace OCA\OAuth2\AppInfo;

use \OCA\OAuth2\Db\AccessTokenMapper;
use \OCA\OAuth2\Db\AuthorizationCodeMapper;
use \OCA\OAuth2\Db\ClientMapper;
use \OCA\OAuth2\Db\RefreshTokenMapper;
use \OCP\AppFramework\App;

class Application extends App {

    /**
     * Application constructor.
     *
     * @param array $urlParams an array with variables extracted from the routes
     */
    public function __construct(array $urlParams=array()){
        parent::__construct('oauth2', $urlParams);

		$container = $this->getContainer();

		$container->registerService('ClientMapper', function($c) {
			return new ClientMapper(
				$c->query('ServerContainer')->getDb()
			);
		});

		$container->registerService('AuthorizationCodeMapper', function($c) {
			return new AuthorizationCodeMapper(
				$c->query('ServerContainer')->getDb()
			);
		});

		$container->registerService('AccessTokenMapper', function($c) {
			return new AccessTokenMapper(
				$c->query('ServerContainer')->getDb()
			);
		});

		$container->registerService('RefreshTokenMapper', function($c) {
			return new RefreshTokenMapper(
				$c->query('ServerContainer')->getDb()
			);
		});
    }

}