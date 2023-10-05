<?php

if ( class_exists('\RaspAP\Tokens\CSRFTokenizer')) {
    $csrfToken = new \RaspAP\Tokens\CSRFTokenizer;
    $csrfToken->ensureCSRFSessionToken();
} else {
    die('class failed to load!');
}


