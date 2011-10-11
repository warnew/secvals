<?
/**

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

   Original author: Zoltan LENGYEL - @warnew

   Email validation by Douglas Lovell

**/

// we could add a second parameter as to what's the required behaviour, 
// force some default value or simly return false/null
// obviously right now the later applies

// also there should be an option for the unknown keys: should we keep or drop them?
// will force drop for now - better to be paranoid :)

function secure_vals($howtosecure = array()){
  global $_SPOST;
  global $_SGET;
  if ($howtosecure && $_POST) {
    $_SPOST = bsg_secure_array($howtosecure,$_POST);
  }
  if ($howtosecure && $_GET) {
    $_SGET = bsg_secure_array($_GET);
  }
}

// securevals originally was a part of bsg, the names kept for backward compatibility 
function bsg_secure_value($key,$value) {
//   $value = preg_replace("/'/","&apos;",$value); // i hate \' -s
//   $value = pg_escape_string($value);
   switch($key) {
     case "email"     : $value = ch_val_email($value); break;
     case "float"     : $value = ch_val_float($value); break;
     case "timestamp" : $value = ch_val_timestamp($value); break; 
     case "natural"   : $value = ch_val_natural($value); break;
     default          : $value = NULL;
   }
   return $value;
}

function bsg_secure_array($howtosecure,$arr) {
  if (!$arr) {
    return;
  }
  foreach ($arr as $key => $value) {
    if (is_array($value)) {
      $value = bsg_secure_array($howtosecure,$value);
    } else {
      $value = bsg_secure_value($howtosecure[$key],$value);
    }
    $rv[$key] = $value;
  }
  return $rv;
}

function ch_val_numeric($v) {
  if (strlen($v) < 1) return NULL;
  if (!is_numeric($v)) return FALSE;
}

function ch_val_natural($v) {
  // for natural numbers, eg. pagination.
  $v = ch_val_2_numeric($v);
  if ($v < 0) {
    return FALSE;
  }
  return $v;
}

function ch_val_float($v) {
  $v = ch_val_2_numeric($v);
  $v = preg_replace('#,#','.',$v); // in some languages we have decimal coma-s instead of decimal point-s
  return $v;
}

function ch_val_timestamp($v) { 
   // we have other formats too, but right now this is enogh for me...
   // YYYY. MM. DD. -> YYYY-MM-DD
  // fixme: this won't validate jusct convert.
  $v = preg_replace('#\. #','-',$v);
  $v = preg_replace('#\.$#','',$v);
  return $v;
}


function ch_val_email($value) {
  if (strlen($value) < 1) return NULL;
  if (validEmail($value)) {
    return $value;
  }
  return FALSE;
}

/**

From the article of Douglas Lovell at http://www.linuxjournal.com/article/9585

Validate an email address.
Provide email address (raw input)
Returns true if the email address has the email 
address format and the domain exists.
*/
function validEmail($email)
{
   $isValid = true;
   $atIndex = strrpos($email, "@");
   if (is_bool($atIndex) && !$atIndex)
   {
      $isValid = false;
   }
   else
   {
      $domain = substr($email, $atIndex+1);
      $local = substr($email, 0, $atIndex);
      $localLen = strlen($local);
      $domainLen = strlen($domain);
      if ($localLen < 1 || $localLen > 64)
      {
         // local part length exceeded
         $isValid = false;
      }
      else if ($domainLen < 1 || $domainLen > 255)
      {
         // domain part length exceeded
         $isValid = false;
      }
      else if ($local[0] == '.' || $local[$localLen-1] == '.')
      {
         // local part starts or ends with '.'
         $isValid = false;
      }
      else if (preg_match('/\\.\\./', $local))
      {
         // local part has two consecutive dots
         $isValid = false;
      }
      else if (!preg_match('/^[A-Za-z0-9\\-\\.]+$/', $domain))
      {
         // character not valid in domain part
         $isValid = false;
      }
      else if (preg_match('/\\.\\./', $domain))
      {
         // domain part has two consecutive dots
         $isValid = false;
      }
      else if
(!preg_match('/^(\\\\.|[A-Za-z0-9!#%&`_=\\/$\'*+?^{}|~.-])+$/',
                 str_replace("\\\\","",$local)))
      {
         // character not valid in local part unless 
         // local part is quoted
         if (!preg_match('/^"(\\\\"|[^"])+"$/',
             str_replace("\\\\","",$local)))
         {
            $isValid = false;
         }
      }
      if ($isValid && !(checkdnsrr($domain,"MX") || checkdnsrr($domain,"A")))
      {
         // domain not found in DNS
         $isValid = false;
      }
   }
   return $isValid;
}

?>
