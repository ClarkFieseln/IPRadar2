# imports
import configuration
import pickle

def save_obj(obj, name):
    with open('obj/'+ name + '.pkl', 'wb') as f:
        pickle.dump(obj, f, pickle.HIGHEST_PROTOCOL)

def load_obj(name):
    with open('obj/' + name + '.pkl', 'rb') as f:
        return pickle.load(f)

# find 2nd occurrence of char/string within a string
def find_2nd(string, substring):
   return string.find(substring, string.find(substring) + 1)

# print information of packet
def print_info_layer(packet):
   try:
      if packet.ip:
         if configuration.PACKED_OUTPUT == False:
            print("{0:5}".format(packet.highest_layer)+": {0:16}".format(packet.ip.src)+"-> {0:16}".format(packet.ip.dst), end='')
         else:
            print(packet.highest_layer + ": " + packet.ip.src + " -> " + packet.ip.dst, end='')
   except AttributeError: # need this? print exception?
      # ignore packets that aren't DNS Request
      print("err333")
      return
   except Exception: # avoid catching exceptions like SystemExit, KeyboardInterrupt, etc.
      return

# print information of geolocations
def print_geolocations(response_src, response_dst, host_src_arg, host_dst_arg):
   try:
      # print locations
      if configuration.PACKED_OUTPUT == False:
         log_location = "(" + response_src.country + ", {0:32}".format(response_src.city) + ", {0:38}".format(host_src_arg) + " -> " + \
                  response_dst.country + ", {0:32}".format(response_dst.city) + ", {0:38}".format(host_dst_arg) + ")"
      else:
         log_location = " (" + response_src.country + "," + response_src.city + "," + host_src_arg + " -> " + \
                  response_dst.country + "," + response_dst.city + "," + host_dst_arg + ")"
      print(log_location)
      return
   except AttributeError:
      print("err111")
      return
   except Exception: # avoid catching exceptions like SystemExit, KeyboardInterrupt, etc.
      print("err222")
      return








