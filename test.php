<?
//test cases for secure vals.
include('secvals.php');

$arr['numeric'] = 'asd';   $howto['numeric'] = 'numeric';

$secured = bsg_secure_array($howto,$arr);

foreach ($arr as $k => $v) {
  print "{$k} => {$v} secured as {$howto[$k]} = {$secured[$k]}\n";
}

?>
