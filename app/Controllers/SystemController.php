<?php

namespace App\Controllers;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Container\ContainerInterface;
use Respect\Validation\Validator as v;
use League\ISO3166\ISO3166;

class SystemController extends Controller
{
    public function providers(Request $request, Response $response)
    {
        if ($_SESSION["auth_roles"] != 0) {
            return $response->withHeader('Location', '/dashboard')->withStatus(302);
        }
        
        if ($request->getMethod() === 'POST') {
            // Retrieve POST data
            $data = $request->getParsedBody();
            $db = $this->container->get('db');
            
            // Error message initialization
            $error = '';

            // Check each field
            foreach ($data as $key => $value) {
                if (empty($value)) {
                    // Construct error message
                    $error .= "Error: '$key' cannot be empty.\n";
                }
            }

            // Display error messages if any
            if (!empty($error)) {
                $this->container->get('flash')->addMessage('error', $error);
                return $response->withHeader('Location', '/registry')->withStatus(302);
            }
            
            try {
                $db->beginTransaction();
                
                $currentDateTime = new \DateTime();
                $crdate = $currentDateTime->format('Y-m-d H:i:s.v'); // Current timestamp
                
                $db->update(
                    'settings',
                    [
                        'value' => $data['registryOperator']
                    ],
                    [
                        'name' => "company_name"
                    ]
                );
                
                $db->update(
                    'settings',
                    [
                        'value' => $data['registryOperatorVat']
                    ],
                    [
                        'name' => "vat_number"
                    ]
                );

                $db->update(
                    'settings',
                    [
                        'value' => $data['contactAddress']
                    ],
                    [
                        'name' => "address"
                    ]
                );
                
                $db->update(
                    'settings',
                    [
                        'value' => $data['contactAddress2']
                    ],
                    [
                        'name' => "address2"
                    ]
                );

                $db->update(
                    'settings',
                    [
                        'value' => $data['contactEmail']
                    ],
                    [
                        'name' => "email"
                    ]
                );
                
                $db->update(
                    'settings',
                    [
                        'value' => $data['contactPhone']
                    ],
                    [
                        'name' => "phone"
                    ]
                );
                
                $db->update(
                    'settings',
                    [
                        'value' => $data['registryHandle']
                    ],
                    [
                        'name' => "handle"
                    ]
                );
                
                $db->update(
                    'settings',
                    [
                        'value' => $data['launchPhases']
                    ],
                    [
                        'name' => "launch_phases"
                    ]
                );
                
                $db->update(
                    'settings',
                    [
                        'value' => $data['verifyPhone']
                    ],
                    [
                        'name' => "verifyPhone"
                    ]
                );
                
                $db->update(
                    'settings',
                    [
                        'value' => $data['verifyEmail']
                    ],
                    [
                        'name' => "verifyEmail"
                    ]
                );
                
                $db->update(
                    'settings',
                    [
                        'value' => $data['verifyPostal']
                    ],
                    [
                        'name' => "verifyPostal"
                    ]
                );
                
                $db->update(
                    'settings',
                    [
                        'value' => $data['whoisServer']
                    ],
                    [
                        'name' => "whois_server"
                    ]
                );
                
                $db->update(
                    'settings',
                    [
                        'value' => $data['rdapServer']
                    ],
                    [
                        'name' => "rdap_server"
                    ]
                );
                
                $db->update(
                    'settings',
                    [
                        'value' => $data['currency']
                    ],
                    [
                        'name' => "currency"
                    ]
                );

                $db->commit();
                $_SESSION['_currency'] = $data['currency'];
            } catch (Exception $e) {
                $db->rollBack();
                $this->container->get('flash')->addMessage('error', 'Database failure: ' . $e->getMessage());
                return $response->withHeader('Location', '/registry')->withStatus(302);
            }

            $currentDateTime = new \DateTime();
            $currentDate = $currentDateTime->format('Y-m-d H:i:s.v'); // Current timestamp
            $db->insert(
                'users_audit',
                [
                    'user_id' => $_SESSION['auth_user_id'],
                    'user_event' => 'settings.update',
                    'user_resource' => 'control.panel',
                    'user_agent' => $_SERVER['HTTP_USER_AGENT'],
                    'user_ip' => get_client_ip(),
                    'user_location' => get_client_location(),
                    'event_time' => $currentDate,
                    'user_data' => null
                ]
            );

            $this->container->get('flash')->addMessage('success', 'Registry details have been updated successfully');
            return $response->withHeader('Location', '/registry')->withStatus(302);
            
        }

        $db = $this->container->get('db');
        //$company_name = $db->selectValue("SELECT value FROM settings WHERE name = 'company_name'");
$company_name='a';
        return view($response,'admin/system/providers.twig', [
            'company_name' => $company_name,
        ]);
    }

}