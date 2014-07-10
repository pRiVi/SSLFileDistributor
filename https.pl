#!perl
 
use strict;
use warnings;
use Socket;
use POE qw(
   Wheel::SocketFactory
   Wheel::ReadWrite
   Driver::SysRW
   Filter::SSL
   Filter::Stackable
   Filter::HTTPD
);

my $capass = `cat /root/filed/capw.txt`;
chomp($capass);
my $datapath = "/tmp/testdata";
my $datadir = "/data/";
my $mkca = "/etc/mkca-dist";
my $ssl = "/usr/bin/openssl";

sub ReadForm {
   my @pairs = split(/&/, shift);
   my $return = {}; 
   foreach my $pair (@pairs) {
      my ($name, $value) = split(/=/, $pair);
      $name =~ tr/+/ /;
      $name =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;
      $value =~ tr/+/ /;
      $value =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;
      $return->{$name} = $value;
   }
   return $return;
}

sub readFile {
   my $filename = shift;
   my $file = '';
   my $in = '';
   open(IN, "<", $filename) || die $filename.":".$!;
   while ((my $size = sysread(IN, $in, 1024*1024)) > 0 ) {
      $file .= $in;
   }
   close(IN);
   return $file;
} 

POE::Session->create(
  inline_states => {
    _start       => sub {
      my $heap = $_[HEAP];
      $heap->{listener} = POE::Wheel::SocketFactory->new(
        BindAddress  => '86.110.76.147',
        BindPort     => 443,
        Reuse        => 'yes',
        SuccessEvent => 'socket_birth',
        FailureEvent => '_stop',
      );
    },
    _stop => sub {
       delete $_[HEAP]->{listener};
    },
    socket_birth => sub {
      my ($socket) = $_[ARG0];
      POE::Session->create(
        inline_states => {
          _start       => sub {
            my ($heap, $kernel, $connected_socket, $address, $port) = @_[HEAP, KERNEL, ARG0, ARG1, ARG2];
            $heap->{sslfilter} = POE::Filter::SSL->new(
               #crt    => '/etc/ssl/certs/www.priv.de.crt', # <- The server certificate for your www.domain.de...
               chain  => '/root/ca.crt', # <- ... as chain if you use startssl.
               key    => '/etc/ssl/private/startssl.private.key', # The private key for the certificate for your www.domain.de
               cacrt  => $mkca.'/ca.crt', # The CA certificate you just created self-sign with mkca-dist
               #blockbadclientcert => 1,
               cipher => 'DHE-RSA-AES256-GCM-SHA384:AES256-SHA',
               #cacrl  => 'ca.crl', # Uncomment this, if you have a CRL file.
               debug  => 1,
               clientcert => 1
            );
            $heap->{socket_wheel} = POE::Wheel::ReadWrite->new(
              Handle     => $connected_socket,
              Driver     => POE::Driver::SysRW->new(),
              Filter     => POE::Filter::Stackable->new(Filters => [
                $heap->{sslfilter},
                POE::Filter::HTTPD->new()
              ]),
              InputEvent => 'socket_input',
              ErrorEvent => '_stop',
            );
          },
          socket_input => sub {
            my ($kernel, $heap, $buf) = @_[KERNEL, HEAP, ARG0];
            my (@certid) = ($heap->{sslfilter}->clientCertIds());
            my $response = HTTP::Response->new(200);
            my $form = undef;
            if (ref($buf) eq "HTTP::Request") {
               $form = ReadForm($buf->content());
            }
            if ($buf->uri =~ m,^/generate/certificate$,) {
               $form->{"name"} =~ s,[^a-zA-Z\s\-\,]+,,g;
               $form->{"email"} =~ s,[^a-zA-Z\s\-\,]+,,g;
               $form->{"email"} ||= 'keine@priv.de';
               system("rm", "-Rf", $mkca."/vpnclients/".$form->{"name"}."/");
               system("mkdir", "-p", $mkca."/vpnclients/".$form->{"name"}); 
               my $spkacname = $mkca."/vpnclients/".$form->{"name"}."/".$form->{"name"}.".spkac";
               my $crtname = $mkca."/vpnclients/".$form->{"name"}."/".$form->{"name"}.".crt";
               # TODO:XXX:FIXME: No support for Internet Explorer, only Firefox/Chrome is supported.
               unless (length($form->{"name"}) > 2) {
                  $response->push_header('Content-type', 'text/html');
                  $response->content("ERROR: No name given");
                  $heap->{socket_wheel}->put($response);
                  $kernel->delay(_stop => 1);
                  return;
               }
               chdir($mkca);
               unless ($form && $form->{"newSPKAC"}) {
                  my $keyname = $mkca."/vpnclients/".$form->{"name"}."/".$form->{"name"}.".key";
                  my $reqname = $mkca."/vpnclients/".$form->{"name"}."/".$form->{"name"}.".csr";
                  my $p12name = $mkca."/vpnclients/".$form->{"name"}."/".$form->{"name"}.".p12";
                  foreach my $curcmd ([$ssl, "genrsa", "-des3", "-out", $keyname, "-passout", "pass:''", "2048"],
                                      [$ssl, "req", "-batch", "-new", "-key", $keyname, "-out", $reqname, "-config", $mkca."/CA.cnf", "-passin", "pass:''", "-subj", '/emailAddress='.$form->{"email"}.'/CN='.$form->{"name"}],
                                      [$ssl, "ca", "-batch", "-in", $reqname, "-config", $mkca."/CA.cnf", "-out", $crtname, "-passin", "pass:".$capass],
                                      [$ssl, "pkcs12", "-export", # "-certfile", $mkca."/ca.crt", 
                                                                    "-clcerts", 
                                              "-in", $crtname, "-inkey", $keyname, "-out", $p12name, "-passin", "pass:''", "-passout", "pass:"]) {
                     print "".join(" ", map { "'".$_."'" } @$curcmd)."\n";
                     system(@$curcmd);
                  }
                  if (my $file = readFile($p12name)) {
                     $response->push_header('Content-type', 'application/x-pkcs12');
                     $response->content($file);
                  } else {
                     $response->push_header('Content-type', 'text/html');
                     $response->content("ERROR: Empty key\n");
                  }
                  $heap->{socket_wheel}->put($response);
                  $kernel->delay(_stop => 1);
                  return;
               }
               $form->{"newSPKAC"} =~ s,[\r\n\0],,g;
               $response->push_header('Content-type', 'application/x-x509-user-cert');
               open(OUT, ">", $spkacname) || die $!;
               print OUT "SPKAC=".$form->{"newSPKAC"}."\n";
               print OUT "CN=".$form->{"name"}."\n";
               print OUT "emailAddress=".$form->{"email"}."\n";
               print OUT "organizationName=orginame\n";
               print OUT "countryName=DE\n";
               print OUT "stateOrProvinceName=st\n";
               print OUT "localityName=localityName\n";
               my $cmd = [$ssl, "ca", "-config", $mkca."/CA.cnf", "-days", "100", "-notext", "-batch", "-spkac", $spkacname, "-passin", "pass:".$capass, "-out", $crtname];
               print "".join(" ", map { "'".$_."'" } @$cmd)."\n";
               system(@$cmd);
               $response->content(readFile($crtname));
               $heap->{socket_wheel}->put($response);
               $kernel->delay(_stop => 5);
            } else {
               my $content = '';
               my $valid = $heap->{sslfilter}->clientCertValid();
               if ($valid) {
                  my $certid = undef;
                  my $name = undef;
                  my $mail = undef;
                  foreach my $curcert (@certid) {
                     next unless $curcert;
                     $certid = $heap->{sslfilter}->hexdump($curcert->[2]);
                     my $line = [split(/\//, $curcert->[0])];
                     my $config = {};
                     foreach my $curline (split(/\//, $curcert->[0])) {
                        my $curkeyval = [split(/\=/, $curline, 2)];
                        next unless $curkeyval->[0];
                        $config->{$curkeyval->[0]} = $curkeyval->[1];
                     }
                     $name = $config->{CN};
                     $mail = $config->{emailAddress};
                  }
                  if (defined($certid) && defined($name) && defined($mail)) {
                     $content .= "Hello <font color=green>valid</font> client ".$name." (ID ".$certid.", ".$mail.")<hr>";
                     if ($buf->uri =~ m,^$datadir([a-zA-Z0-9\-\.\/]*)$,) {
                        my $path = $1;
                        $path =~ s,\.\.,\.,gi;
                        my $curfolder = $datapath."/".$certid."/".$path;
                        my $parentlinkfolder = $path;
                        $parentlinkfolder =~ s,(\/|^)[^\/]*?$,,;
                        $content .= "Location: /".$path."<hr>\n";
                        if (-d $curfolder) {
                           if (opendir(DIR, $curfolder)) {
                              $content .= "<table>";
                              while(my $curentry = readdir(DIR)) {
                                 next if ($curentry =~ /^\.$/);
                                 my $curlink = undef;
                                 if ($curentry =~ /^\.\.$/) {
                                    next unless $path;
                                    $curlink = $parentlinkfolder;
                                 } else {
                                    $curlink .= ($path ? $path."/" : "").$curentry;
                                 }
                                 $content .= "<tr><td>";
                                 if (-d $curfolder."/".$curentry) {
                                    $content .= " [DIR]";
                                 } elsif(-f $curfolder."/".$curentry) {
                                    $content .= " [FILE]"; 
                                 }
                                 $content .= "</td><td>";
                                 $content .= "<a href='".$datadir.$curlink."'>".$curentry."</a>";
                                 $content .= "</td></tr>\n";
                              }
                              $content .= "</table>\n";
                           } else {
                              print "ERROR1: ".$!."\n";
                              $content .= "Internal error 1<br>\n";
                           }
                        } elsif(-f $curfolder) {
                           if (open(IN, "<", $curfolder)) {
                              my $file = '';
                              while(<IN>) {
                                 $file .= $_;
                              }
                              $response->push_header('Content-type', 'application/force-download');
                              $response->content($file);
                              $heap->{socket_wheel}->put($response);
                              $kernel->delay(_stop => 1);
                              return;
                           } else {
                              print "ERROR2: ".$!."\n";
                              $content .= "Internal error 2<br>\n";
                           }
                        } else {
                           $content .= $path." not found!";
                        }
                        $content .= "<hr>";
                     } else {
                        $content .= "<a href='".$datadir."'>Show your files</a><hr>";
                     }
                  } else {
                     $content .= "Internal error parsing your client certificate.<br><br>";
                  }
               } else {
                  $content .= "None or <font color=red>invalid</font> X:".$valid." client certificate.<br><br>Please generate one:<br><br>";
                  $content .= '<form action="/generate/certificate" method="POST"><table>'.
                     '<tr><td>Name</td><td><input name=name></td></tr>'.
                     "<tr><td>E-Mail</td><td><input name=email></td></tr>".
                     '<tr><td>Keysize</td><td><keygen challenge="replaceMe" keyparams="2048" keytype="rsa" name="newSPKAC"></keygen></td></tr>'.
                     '<tr><td colspan=2><input type="submit" value="Create certificate" /></td></tr></table></form>';
               }
               if ($buf->uri =~ m,^/debug/,) {
                  $content .= "<hr>";
                  foreach my $certid (@certid) {
                     $certid = $certid ? $certid->[0]."<br>".$certid->[1]."<br>SERIAL=".$heap->{sslfilter}->hexdump($certid->[2]) : 'No client certificate';
                     $content .= $certid."<hr>";
                  }
                  $content .= "Your URL was: ".$buf->uri."<hr>";
                  $content .= localtime(time())."<br>\n";;
               }
               $response->push_header('Content-type', 'text/html');
               $response->content($content);
               $heap->{socket_wheel}->put($response);
               $kernel->delay(_stop => 1);
            }
          },
          _stop => sub {
            delete $_[HEAP]->{socket_wheel};
          }
        },
        args => [$socket],
      );
    }
  }
);
 
$poe_kernel->run();
