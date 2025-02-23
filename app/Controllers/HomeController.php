<?php

namespace App\Controllers;

use App\Models\User;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Container\ContainerInterface;

class HomeController extends Controller
{
    public function index(Request $request, Response $response)
    {
        $basePath = '/var/www/cp/resources/views/';
        $template = file_exists($basePath . 'index.custom.twig') 
                    ? 'index.custom.twig' 
                    : 'index.twig';
        return view($response, $template, [
            'whois_server' => $whois_server,
            'rdap_server' => $rdap_server,
            'company_name' => $company_name,
            'email' => $email
        ]);
    }

    public function dashboard(Request $request, Response $response)
    {
        $db = $this->container->get('db');

        if ($_SESSION['auth_roles'] === 0) {
            $clid = null;
        } else {
            $result = $db->selectRow('SELECT zone_id FROM zone_users WHERE user_id = ?', [$_SESSION['auth_user_id']]);
            if (is_array($result)) {
                $clid = $result['zone_id'];
            } else if (is_object($result) && method_exists($result, 'fetch')) {
                $clid = $result->fetch();
            } else {
                $clid = null;
            }
        }

        if ($clid !== null) {
            $zones = $db->selectValue('SELECT count(id) as zones FROM zones WHERE client_id = ?', [$clid]);
            
            return view($response, 'admin/dashboard/index.twig', [
                'zones' => $zones,
            ]);
        } else {
            $zones = $db->selectValue('SELECT count(id) as zones FROM zones');

            return view($response, 'admin/dashboard/index.twig', [
                'zones' => $zones,
            ]);
        }
    }

    public function mode(Request $request, Response $response)
    {
        if (isset($_SESSION['_screen_mode']) && $_SESSION['_screen_mode'] == 'dark') {
            $_SESSION['_screen_mode'] = 'light';
        } else {
            $_SESSION['_screen_mode'] = 'dark';
        }
        $referer = $request->getHeaderLine('Referer');
        if (!empty($referer)) {
            return $response->withHeader('Location', $referer)->withStatus(302);
        }
        return $response->withHeader('Location', '/dashboard')->withStatus(302);
    }

    public function lang(Request $request, Response $response)
    {
        $data = $request->getQueryParams();
        if (!empty($data)) {
            $_SESSION['_lang'] = array_key_first($data);
        } else {
            unset($_SESSION['_lang']);
        }
        $referer = $request->getHeaderLine('Referer');
        if (!empty($referer)) {
            return $response->withHeader('Location', $referer)->withStatus(302);
        }
        return $response->withHeader('Location', '/dashboard')->withStatus(302);
    }
}