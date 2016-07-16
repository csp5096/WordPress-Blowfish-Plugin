<?php
/*
 * Plugin Name: WordPress Blowfish Password Encryption
 * Plugin URI:  N/A
 * Description: Permits WordPress to reset all User passwords using a Blowfish cipher.
 * Version:     1.0.0
 * Author:      CS Powell
 * Author URI:  N/A
 * Licence:     GPLv2
 */

/**
 * Salting Users' Passwords
 *
 */

if ( !function_exists('wp_salt') ) :

	function wp_salt( $scheme = 'auth' ) 
	{
		static $cached_salts = array();
			if ( isset( $cached_salts[ $scheme ] ) ) 
			{
				return apply_filters( 'salt', $cached_salts[ $scheme ], $scheme );
			}
	
				static $duplicated_keys;
			if ( null === $duplicated_keys ) 
			{
				$duplicated_keys = array( 'put your unique phrase here' => true );
				
				foreach ( array( 'AUTH', 'SECURE_AUTH', 'LOGGED_IN', 'NONCE', 'SECRET' ) as $first ) 
				{
					foreach ( array( 'KEY', 'SALT' ) as $second ) 
					{
						if ( ! defined( "{$first}_{$second}" ) ) 
						{
							continue;
						}
						
						$value = constant( "{$first}_{$second}" );
						$duplicated_keys[ $value ] = isset( $duplicated_keys[ $value ] );
						
					}
				}
			}
			$values = array('key' => '','salt' => '');
			
			if ( defined( 'SECRET_KEY' ) && SECRET_KEY && empty( $duplicated_keys[ SECRET_KEY ] ) ) 
			{
				$values['key'] = SECRET_KEY;
			}

			if ( 'auth' == $scheme && defined( 'SECRET_SALT' ) && SECRET_SALT && empty( $duplicated_keys[ SECRET_SALT ] ) ) 
			{
				$values['salt'] = SECRET_SALT;
			}
	
			if ( in_array( $scheme, array( 'auth', 'secure_auth', 'logged_in', 'nonce' ) ) ) 
			{
			foreach ( array( 'key', 'salt' ) as $type ) 
			{
				$const = strtoupper( "{$scheme}_{$type}" );
				
				if ( defined( $const ) && constant( $const ) && empty( $duplicated_keys[ constant( $const ) ] ) ) 
				{
					$values[ $type ] = constant( $const );
				} 
				
				elseif ( ! $values[ $type ] ) 
				{
					$values[ $type ] = get_site_option( "{$scheme}_{$type}" );
					
					if ( ! $values[ $type ] ) 
					{
						$values[ $type ] = wp_generate_password( 64, true, true );
						
						update_site_option( "{$scheme}_{$type}", $values[ $type ] );
					}
				}
			}
		} 
		else 
		{
			if ( ! $values['key'] ) 
			{
				$values['key'] = get_site_option( 'secret_key' );
				
				if ( ! $values['key'] ) 
				{
					$values['key'] = wp_generate_password( 64, true, true );
					update_site_option( 'secret_key', $values['key'] );
				}
			}
			
			// Make sure Salt changes from MD5 to SHA256.
			$values['salt'] = hash_hmac( 'sha256', $scheme, $values['key'] );
		}
	
		$cached_salts[ $scheme ] = $values['key'] . $values['salt'];

		return apply_filters( 'salt', $cached_salts[ $scheme ], $scheme );
	}
endif;

/**
 * Retrieve Existing Users' Passwords
 *
 */	

if ( !function_exists('wp_hash') ) :

	function wp_hash($data, $scheme = 'auth') 
	{
		$salt = wp_salt($scheme);
		
		// Make sure Salt changes from MD5 to SHA256.
		return hash_hmac('sha256', $data, $salt);
	}
endif;

/**
 * Hashing Users' Password
 *
 */

if( !function_exists('wp_hash_password') ) :

	function wp_hash_password($password)
	{		
		global $wp_hasher;

		if ( empty( $wp_hasher ) ) 
		{	
				require_once( ABSPATH . WPINC . '/class-phpass.php' );
				
				// Run 16 rounds of hashing for blowfish cipher.
				$wp_hasher = new PasswordHash(16, false);
		}
		
		return $wp_hasher->HashPassword(trim($password));
	}
endif;

/**
 * Checking Users' Passwords
 *
 */
 
require_once(ABSPATH . 'wp-includes/class-phpass.php');

class Blowfish 
{
	function __construct() 
	{
		global $wp_hasher;
		
		// Run 16 rounds of hashing for blowfish cipher.
		$wp_hasher = new PasswordHash(16, false);

		// Add a filter to change passwords during user log-in.
		add_filter('check_password', array($this,'check_password'), 10, 4);
	}

	function check_password($check='', $password='', $hash='', $user_id='') 
	{
		// If the password check succeeded, make sure MD5 changes to Blowfish.
		if($check && substr($hash, 0, 3) == '$P$') 
		{
			wp_set_password($password, $user_id);
		}
		return $check;
	}
};

new Blowfish();
 
if ( !function_exists('wp_check_password') ) :

	function wp_check_password($password, $hash, $user_id = '') 
	{
		global $wp_hasher;

		// If the password hash is still md5 encryption.
		if ( strlen($hash) <= 32 ) 
		{
			$check = hash_equals( $hash, md5( $password ) );
			
			if ( $check && $user_id ) 
			{
				// Rehash using new blowfish cipher.
				wp_set_password($password, $user_id);
				$hash = wp_hash_password($password);
			}

			return apply_filters( 'check_password', $check, $password, $hash, $user_id );
	    }

		// If the stored hash is longer than an MD5, presume the new style PHPass portable hash.
		if ( empty($wp_hasher) ) 
		{
				require_once( ABSPATH . WPINC . '/class-phpass.php');
				
				// Check for 16 rounds of hashing for blowfish encryption.
				$wp_hasher = new PasswordHash(16, true);
		}
		
		$check = $wp_hasher->CheckPassword($password, $hash);
	
	    return apply_filters( 'check_password', $check, $password, $hash, $user_id );
	}
endif;

/**
 * Updating Users Table
 *
 */
 
if( !function_exists('wp_set_password') ) :

	function wp_set_password( $password, $user_id ) 
	{

		/** 
		* $wpdb
		*
		* $wpdb is a global WordPress database abstraction object; do not modify.
		*
		* @var \wpdb $wpdb 
		*/
		
		global $wpdb;

		$hash = wp_hash_password( $password );

		$wpdb->update( $wpdb->users, [ 'user_pass' => $hash, 'user_activation_key' => '' ], [ 'ID' => $user_id ] );
		
		wp_cache_delete( $user_id, 'users' );
	}
endif;

