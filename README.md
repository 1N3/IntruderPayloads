# IntruderPayloads
Collection of personal Burpsuite Intruder payloads and fuzz lists



InjectX to Find XSS

Author: 1N3 @ CrowdShield
Website: https://crowdshield.com
Date: 10/29/2015

Overview

In this tutorial, I will cover a simple technique to identify reflected values in a target web application and easily locate potential XSS vectors. This is accomplished by injecting unique heuristic values automatically via Burpsuite Intruder and using search strings to easily locate reflected values. In order to use this technique, you’ll need Burpsuite along with the custom grep strings and fuzz lists provided in this tutorial to get started. For more advanced tricks covered at the end of this tutorial, you’ll also need Apache and Beef (Browser Exploitation Framework).


Why is this helpful to me?

Using this technique allows you to do the following:

Find reflected values quickly
Find the location of all reflected values in the response
Receive XSS confirmation via heuristic testing and unique strings
Exploit XSS vectors with certainty


Great! How do I do it?

Download the Burp attack configuration or manual fuzz and grep strings here
Load the attack configuration or manual payload lists from the Burp Intruder menu
Copy/paste the request to the Intruder screen and add injection points
NOTE: You’ll need to copy/paste the hostname into the “Host” tab of the Intruder configuration for this to work. 
Run the attack and analyze the results
If XSS is possible, proceed to “real” XSS exploitation


Workflow:

Is the injection point reflected in the response? If yes, goto step 2.
If reflected in the response, where in the response is it reflected? Search for “INJECTX” to find all injection points. Go to step 3.
Once reflected injection points are found, which characters are being sanitized? Again, search for “INJECTX” in the response and look for the heuristic test characters to see which are still untampered. At a minimum, we’ll need “‘></(). To make this easier, you can create searchable columns in Burpsuite and specify “INJECTX”, “</INJECTX>” and “(INJECTX)” as your grep strings. If these characters or search strings are found, then XSS is possible. Proceed to step 4.
If XSS is possible, inject our “real” XSS payloads either through manual browser attempts, Burp Intruder or Repeater to exploit the XSS vector.


Remote confirmation via Apache logs can help to keep track of blind XSS injection points and will also list the referring page the XSS loaded along with the source IP. Since we control the iframe_injection.php page, we can inject whatever HTML/JS code we want. 

In this case, it loads a Beef (Browser Exploitation Framework) hook.js which can be used to launch more advanced XSS/client side attacks.
