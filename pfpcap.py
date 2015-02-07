#!/usr/bin/python

import re
import mechanize
import urllib

class PeakflowBrowser:

    def __init__(self, host, username, password):
        if host is None:
            raise ValueError("Peakflow host must be provided")
        if username is None:
            raise ValueError("Username to Peakflow must be provided")
        if password is None:
            raise ValueError("password to Peakflow must be provided")
        self.base_url = "https://%s" % host
        self.username = username
        self.password = password

        # common POST parameters
        # TODO: what is widget_id? Looks like a randomly generated ID of some
        # form but it is persistent across logins and is not related to the
        # logged in user. Is it per system?
        self.post_params = {
                'id': 'flowtap',
                'flowtap_filter_type': 'fcap_filter',
                'prepcapfilename': '%2Fdata%2Ftmp%2Fqueries%2Fsample_packets_tms.xml.1337',
                'widget_id': 'MitigationFlowTapWidget_b874baea1dc6c372c9824eebc4f95d8c',
                'altreq': 1,
                'sprpcv': 2,
                'popup': 1
            }

        self.br = mechanize.Browser()
        self.br.set_handle_robots(False) 
        self._do_login()



    def _do_login(self):
        """ Handle login
        """
        self.br.open(self.base_url)
        self.br.select_form(name="auth")
        self.br["username"] = self.username
        self.br["password"] = self.password
        self.br.submit()


    def logout(self):
        """ Logout of the Web UI
        """
        self.br.open(self.base_url + '/?logout=true')


    def _get_mitigation(self, mitigation_id):
        """ Get the mitigation details page

            This is also necessary before trying to start a flow capture as
            certain session variables on the server side are set when going to
            this URL and without them being set, the server will reject us from
            starting the flow capture.
        """
        resp = self.br.open(self.base_url + '/page?id=mitigation_status&mitigation_id=' + str(mitigation_id))



    def start_flowcapture(self, mitigation_id, tms_ip):
        """ Start a flow capture

            Returns True if all went well and raises an exception otherwise
        """
        parameters = self.post_params.copy()
        parameters.update({
            'tms_ip': tms_ip,
            'mitigation_id': mitigation_id,
            'rpc': 'start_recording'
            })
        data = urllib.urlencode(parameters)
        resp = self.br.open(self.base_url + '/wizards/flowtap?id=flowtap', data)
        body = str(resp.read())
        if re.search('Access Denied', body):
            # To start a flow capture the server checks that certain server side
            # session variables are set that define our privileges. Those
            # variables are set (among others?) on the mitigation details page,
            # so if we receive 'Access Denied' we do a dummy get of mitigation
            # info to set the proper session variables and then call this
            # function again.
            # XXX: Beware of infinite recursion?
            self._get_mitigation(mitigation_id)
            return self.start_flowcapture(mitigation_id, tms_ip)

        if re.search('FlowTap.finishStartRecordingPackets()', body):
            return True

        raise Exception("Something went wrong")



    def is_flowcapture_finished(self, mitigation_id, tms_ip):
        """ Check if flow capture is done
        """
        parameters = self.post_params.copy()
        parameters.update({
            'tms_ip': tms_ip,
            'mitigation_id': mitigation_id,
            'rpc': 'check_status'
            })
        data = urllib.urlencode(parameters)
        resp = self.br.open(self.base_url + '/wizards/flowtap?id=flowtap', data)
        body = str(resp.read())
        if re.search('Access Denied', body):
            # To start a flow capture the server checks that certain server side
            # session variables are set that define our privileges. Those
            # variables are set (among others?) on the mitigation details page,
            # so if we receive 'Access Denied' we do a dummy get of mitigation
            # info to set the proper session variables and then call this
            # function again.
            # XXX: Beware of infinite recursion?
            self._get_mitigation(mitigation_id)
            return self.is_flowcapture_finished(mitigation_id, tms_ip)

        if re.search('FlowTap.finishRecordingPackets\(true\)', body):
            return True

        return False



    def download_pcap(self, mitigation_id, tms_ip, filename):
        """ Download a finished flowcapture file
        """
        parameters = self.post_params.copy()
        parameters.update({
            'tms_ip': tms_ip,
            'mitigation_id': mitigation_id,
            'rpc': 'download_pcap'
            })
        data = urllib.urlencode(parameters)
        resp = self.br.retrieve(self.base_url + '/wizards/flowtap?id=flowtap',
                filename=filename, data=data)



if __name__ == '__main__':
    import optparse
    parser = optparse.OptionParser()
    parser.add_option("-H", "--host", help="host for SOAP API connection, typically the leader")
    parser.add_option("-U", "--username", help="username for SOAP API connection")
    parser.add_option("-P", "--password", help="password for SOAP API connection")
    parser.add_option("--tms-ip", help="Management IP address of TMS")

    parser.add_option("--start", type="int", metavar="ID", help="start flow capture for mitigation with ID")
    parser.add_option("--status", type="int", metavar="ID", help="check status of flow capture for mitigation with ID")
    parser.add_option("--download", type="int", metavar="ID", help="download completed flow capture for mitigation with ID")

    (options, args) = parser.parse_args()

    pb = PeakflowBrowser(options.host, options.username, options.password)

    if not options.tms_ip:
        print >> sys.stderr, "You have to provide the management IP address of the TMS you wish to capture on"
        pb.logout()
        sys.exit(1)

    if options.start:
        print "Starting flow capture... ",
        if pb.start_flowcapture(options.start, options.tms_ip):
            print "done"
        else:
            print "FAIL (for some reason...)"

    if options.status:
        print "Checking status of flow capture for mitigation id: %s" % options.status
        if pb.is_flowcapture_finished(options.status, options.tms_ip):
            print "Flow capture is done!"
        else:
            print "Flow capture is still running..."

    if options.download:
        if pb.start_flowcapture(options.download, options.tms_ip):
            print "Flow capture successfully started"
        else:
            print "Unable to start flow capture"
            pb.logout()
            sys.exit(1)
        while not pb.is_flowcapture_finished(options.download, options.tms_ip):
            print "Flow capture not done...."
        print "Flow capture complete, downloading pcap..."
        pb.download_pcap(options.download, options.tms_ip, 'damp.pcap')

    pb.logout()
