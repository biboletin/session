<?php
/**
 * Example script demonstrating the usage of the Session class.
 * 
 * This script shows how to create, configure, use, and destroy a session.
 */

use Biboletin\Session\Session;

// Include Composer autoloader
include __DIR__ . '/vendor/autoload.php';

// Create a new Session instance
$session = new Session();

// Configure session parameters
$session->setSavePath(__DIR__ . '/tmp/sessions'); // Set the directory where session files will be stored
$session->setDomain($_SERVER['HTTP_HOST']); // Set the domain for the session cookie
$session->setSecure(true); // Ensure the session cookie is only sent over HTTPS
$session->regenerateId(true); // Regenerate the session ID and delete the old session
$session->setHttpOnly(true); // Make the session cookie inaccessible to JavaScript
$session->setLifeTime(3600); // Set session lifetime to 1 hour (3600 seconds)

// Start the session
$session->start();

// Set session data
$session->set('user', 'John Doe'); // Store user name in session
$session->set('role', 'admin'); // Store user role in session

// Debugging lines (commented out)
dd($session->get('user'), $_SESSION);
// dd($session, session_save_path(), ini_get('session.save_path'));
echo session_save_path();
// Destroy the session
// $session->destroy();
// $session->purge();

// Dump the session object for debugging
dd($session);
