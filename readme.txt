=== WP Password Grok ===

Contributor(s): CS Powell
Tags: password, hash, salt, bcrypt, blowfish, pluggable, security
Requires at least WordPress: 4.0
Tested up to WordPress: 4.5.2
Stable tag: 1.0.0
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

== Description ==

1. wp-blowfish is a WordPress plugin that permits WordPress to reset all User passwords using a Blowfish cipher.

2. Default Settings: Replaces WordPress' outdated and insecure MD5-based password hashing encryption 
with the up-to-date and secure Bcrypt blowfish hashing encryption.

3. This plugin requires PHP 5.5.0  or greater

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/` directory, 
or install the plugin through the WordPress plugins screen directly.

2. Next, activate the plugin through the 'Plugins' screen in WordPress.

=== Manual installation as a must-use plugin ===

1. If not utilizing Composer, you may manually copy the plug-in folder directly into WordPress' `/wp-content/plugins/mu-plugins/` directory.

2. Do not recommend using this as a normal (non-mu) plugin because this makes it too easy to disable or remove the plugin from WordPress.


== Change Log ==

= 1.0.0 =
First edition
