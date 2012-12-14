<?php  defined('SYSPATH') or die('No direct script access.');
/**
 * Created by JetBrains PhpStorm.
 * User : Andrew Scherbakov
 * Date : 05.11.12
 * Time : 10:53
 * File : oauth.php
 *
 * @name oauth
 * @packages Wordpress/ThemeFramework/oauth
 * @subpackage
 * @category
 * @author Andrew Scherbakov
 * @version 0.1
 * @copyright ®©Andrew Scherbakov
 * To change this template use File | Settings | File Templates.
 */
return array(
  'dropbox'    => array(
    'oauth_version'                => '1.0',
    'request_token_url'            => 'https://api.dropbox.com/1/oauth/request_token',
    'dialog_url'                   => 'https://www.dropbox.com/1/oauth/authorize',
    'append_state_to_redirect_uri' => 'state',
    'access_token_url'             => 'https://api.dropbox.com/1/oauth/access_token',
    'authorization_header'         => FALSE,
    'url_parameters'               => FALSE,
    'client_id'                    => '',
    'client_secret'                => '',
    'redirect_uri'                 => '',
    'scope'                        => '',
    'debug'                        => FALSE,
    'debug_http'                   => FALSE,
  ),
  'facebook'   => array(
    'oauth_version'                => '2.0',
    'request_token_url'            => '',
    'dialog_url'                   => 'https://www.facebook.com/dialog/oauth?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&state={STATE}',
    'append_state_to_redirect_uri' => 'state',
    'access_token_url'             => 'https://graph.facebook.com/oauth/access_token',
    'authorization_header'         => TRUE,
    'url_parameters'               => FALSE,
    'client_id'                    => '',
    'client_secret'                => '',
    'redirect_uri'                 => '',
    'scope'                        => '',
    'debug'                        => FALSE,
    'debug_http'                   => FALSE,
  ),
  'flickr'     => array(
    'oauth_version'                => '1.0a',
    'request_token_url'            => 'http://www.flickr.com/services/oauth/request_token',
    'dialog_url'                   => 'http://www.flickr.com/services/oauth/authorize',
    'append_state_to_redirect_uri' => 'state',
    'access_token_url'             => 'http://www.flickr.com/services/oauth/access_token',
    'authorization_header'         => FALSE,
    'url_parameters'               => FALSE,
    'client_id'                    => '',
    'client_secret'                => '',
    'redirect_uri'                 => '',
    'scope'                        => '',
    'debug'                        => FALSE,
    'debug_http'                   => FALSE,
  ),
  'foursquare' => array(
    'oauth_version'                => '2.0',
    'request_token_url'            => '',
    'dialog_url'                   => 'https://foursquare.com/oauth2/authorize?client_id={CLIENT_ID}&scope={SCOPE}&response_type=code&redirect_uri={REDIRECT_URI}&state={STATE}',
    'append_state_to_redirect_uri' => 'state',
    'access_token_url'             => 'https://foursquare.com/oauth2/access_token',
    'authorization_header'         => TRUE,
    'url_parameters'               => FALSE,
    'client_id'                    => '',
    'client_secret'                => '',
    'redirect_uri'                 => '',
    'scope'                        => '',
    'debug'                        => FALSE,
    'debug_http'                   => FALSE,
  ),
  'github'     => array(
    'oauth_version'                => '2.0',
    'request_token_url'            => '',
    'dialog_url'                   => 'https://github.com/login/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&state={STATE}',
    'append_state_to_redirect_uri' => 'state',
    'access_token_url'             => 'https://github.com/login/oauth/access_token',
    'authorization_header'         => TRUE,
    'url_parameters'               => FALSE,
    'client_id'                    => '',
    'client_secret'                => '',
    'redirect_uri'                 => '',
    'scope'                        => '',
    'debug'                        => FALSE,
    'debug_http'                   => FALSE,
  ),
  'google'     => array(
    'oauth_version'                => '2.0',
    'request_token_url'            => '',
    'dialog_url'                   => 'https://accounts.google.com/o/oauth2/auth?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&state={STATE}',
    'append_state_to_redirect_uri' => 'state',
    'access_token_url'             => 'https://accounts.google.com/o/oauth2/token',
    'authorization_header'         => TRUE,
    'url_parameters'               => FALSE,
    'client_id'                    => '',
    'client_secret'                => '',
    'redirect_uri'                 => '',
    'scope'                        => '',
    'debug'                        => FALSE,
    'debug_http'                   => FALSE,
  ),
  'microsoft'  => array(
    'oauth_version'                => '2.0',
    'request_token_url'            => '',
    'dialog_url'                   => 'https://login.live.com/oauth20_authorize.srf?client_id={CLIENT_ID}&scope={SCOPE}&response_type=code&redirect_uri={REDIRECT_URI}&state={STATE}',
    'append_state_to_redirect_uri' => 'state',
    'access_token_url'             => 'https://login.live.com/oauth20_token.srf',
    'authorization_header'         => TRUE,
    'url_parameters'               => FALSE,
    'client_id'                    => '',
    'client_secret'                => '',
    'redirect_uri'                 => '',
    'scope'                        => '',
    'debug'                        => FALSE,
    'debug_http'                   => FALSE,
  ),
  'tumblr'     => array(
    'oauth_version'                => '1.0a',
    'request_token_url'            => 'http://www.tumblr.com/oauth/request_token',
    'dialog_url'                   => 'http://www.tumblr.com/oauth/authorize',
    'append_state_to_redirect_uri' => 'state',
    'access_token_url'             => 'http://www.tumblr.com/oauth/access_token',
    'authorization_header'         => TRUE,
    'url_parameters'               => FALSE,
    'client_id'                    => '',
    'client_secret'                => '',
    'redirect_uri'                 => '',
    'scope'                        => '',
    'debug'                        => FALSE,
    'debug_http'                   => FALSE,
  ),
  'twitter'    => array(
    'oauth_version'                => '1.0a',
    'request_token_url'            => 'https://api.twitter.com/oauth/request_token',
    'dialog_url'                   => 'https://api.twitter.com/oauth/authenticate',
    'append_state_to_redirect_uri' => 'state',
    'access_token_url'             => 'https://api.twitter.com/oauth/access_token',
    'authorization_header'         => TRUE,
    'url_parameters'               => TRUE,
    'client_id'                    => '',
    'client_secret'                => '',
    'redirect_uri'                 => '',
    'scope'                        => '',
    'debug'                        => FALSE,
    'debug_http'                   => FALSE,
  ),
  'vkontakte'   => array(
    'oauth_version'                => '2.0',
    'request_token_url'            => '',
    //'dialog_url'                   => 'https://oauth.vk.com/authorize?client_id={CLIENT_ID}&scope={SCOPE}&redirect_uri={REDIRECT_URI}&response_type=token&display=popup',
    'dialog_url'                   => 'https://oauth.vk.com/authorize?client_id={CLIENT_ID}&scope={SCOPE}&redirect_uri={REDIRECT_URI}&response_type=code',
    'append_state_to_redirect_uri' => 'state',
    'access_token_url'             => 'https://oauth.vk.com/access_token',
    'authorization_header'         => TRUE,
    'url_parameters'               => TRUE,
    'client_id'                    => '',
    'client_secret'                => '',
    'redirect_uri'                 => '',
    'scope'                        => 'wall,status',
    'debug'                        => FALSE,
    'debug_http'                   => FALSE,
  ),
  'yahoo'      => array(
    'oauth_version'                => '1.0a',
    'request_token_url'            => 'https://api.login.yahoo.com/oauth/v2/get_request_token',
    'dialog_url'                   => 'https://api.login.yahoo.com/oauth/v2/request_auth',
    'append_state_to_redirect_uri' => 'state',
    'access_token_url'             => 'https://api.login.yahoo.com/oauth/v2/get_token',
    'authorization_header'         => FALSE,
    'url_parameters'               => FALSE,
    'client_id'                    => '',
    'client_secret'                => '',
    'redirect_uri'                 => '',
    'scope'                        => '',
    'debug'                        => FALSE,
    'debug_http'                   => FALSE,
  ),

);
