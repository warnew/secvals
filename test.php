<?
//test cases for secure vals.
//should write a curl one though

include('secvals.php');

$arr['numeric']  = '123';    $howto['numeric'] = 'numeric';

$secured = bsg_secure_array($howto,$arr);

foreach ($arr as $k => $v) {
  print "{$k} => {$v} secured as {$howto[$k]} = {$secured[$k]}\n";
  print is_numeric($v);
}

?>
