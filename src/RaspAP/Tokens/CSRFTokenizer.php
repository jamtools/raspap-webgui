<?php

/**
 * CSRF tokenizer class
 *
 * @description CSRF tokenizer class for RaspAP
 * @author      Bill Zimmerman <billzimmerman@gmail.com>
 * @author      Martin Glaß <mail@glasz.org>
 * @license     https://github.com/raspap/raspap-webgui/blob/master/LICENSE
 */

declare(strict_types=1);

namespace RaspAP\Tokens;

class CSRFTokenizer
{

    // Constructor
    public function __construct()
    {
        $this->ensureSession();
        if ($this->csrfValidateRequest() && !$this->CSRFValidate()) {
            $this->handleInvalidCSRFToken();
        }
    }

    /**
     * Saves a CSRF token in the session
     */
    public function ensureCSRFSessionToken()
    {
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
    }

    /**
     * Add CSRF Token to form
     */
    public function CSRFTokenFieldTag()
    {
        $token = htmlspecialchars($_SESSION['csrf_token']);
        return '<input type="hidden" name="csrf_token" value="' . $token . '">';
    }

    /**
     * Retuns a CSRF meta tag (for use with xhr, for example)
     */
    public function CSRFMetaTag()
    {
        $token = htmlspecialchars($_SESSION['csrf_token']);
        return '<meta name="csrf_token" content="' . $token . '">';
    }

    /**
     * Validates a CSRF Token
     */
    public function CSRFValidate()
    {
        if(isset($_POST['csrf_token'])) {
            $post_token   = $_POST['csrf_token'];
            $header_token = $_SERVER['HTTP_X_CSRF_TOKEN'];

            if (empty($post_token) && empty($header_token)) {
                return false;
            }
            $request_token = $post_token;
            if (empty($post_token)) {
                $request_token = $header_token;
            }
            if (hash_equals($_SESSION['csrf_token'], $request_token)) {
                return true;
            } else {
                error_log('CSRF violation');
                return false;
            }
        }
    }

    /**
     * Should the request be CSRF-validated?
     */
    public function csrfValidateRequest()
    {
        $request_method = strtolower($_SERVER['REQUEST_METHOD']);
        return in_array($request_method, [ "post", "put", "patch", "delete" ]);
    }

    /**
     * Handle invalid CSRF
     */
    public function handleInvalidCSRFToken()
    {
        if (function_exists('http_response_code')) { 
            http_response_code(500);
            echo 'Invalid CSRF token';
        } else {
            header('HTTP/1.1 500 Internal Server Error');
            header('Content-Type: text/plain');
            echo 'Invalid CSRF token';
        }
        exit;
    }
    
    protected function ensureSession()
    {
        if (session_status() == PHP_SESSION_NONE) {
            session_start();
        }
    } 
}

