import xml.etree.ElementTree as ET
import pandas as pd



#cols_to_keep = ['Elapsed Time (sec)', 'IP Protocol', 'Packets Sent', 'Packets Received', 'Bytes Sent', 'Bytes Received', 'Threat/Content Type', 'Action']
cols_to_keep = ['elapsed', 'proto', 'pkts_sent', 'pkts_received', 'bytes_sent', 'bytes_received', 'src']