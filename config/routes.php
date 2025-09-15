<?php

declare(strict_types=1);
/**
 * This file is part of Hyperf.
 *
 * @link     https://www.hyperf.io
 * @document https://hyperf.wiki
 * @contact  group@hyperf.io
 * @license  https://github.com/hyperf/hyperf/blob/master/LICENSE
 */
use Hyperf\HttpServer\Router\Router;

Router::addRoute(['GET', 'POST', 'HEAD'], '/', 'App\Controller\IndexController@index');
Router::addRoute(['GET', 'POST', 'HEAD'], '/upload', 'App\Controller\IndexController@uploadFile');
Router::addRoute(['GET', 'POST', 'HEAD'], '/test', 'App\Controller\IndexController@test');
Router::addRoute(['GET', 'POST', 'HEAD'], '/sign', 'App\Controller\IndexController@sign');
Router::addRoute(['GET', 'POST', 'HEAD'], '/sign-personal', 'App\Controller\IndexController@signAsPerson');

Router::get('/favicon.ico', function () {
    return '';
});
