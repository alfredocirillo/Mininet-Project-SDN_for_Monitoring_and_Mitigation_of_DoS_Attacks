import json

class Blocklist():
    def __init__(self, filename =None):
        '''
        Class to keep track of the blocked flows/hosts \\
        Parameters are: \\
            - int_blocked = are the flows/hosts blocked by PolicyMaker
            - ext_blocked = are the flows/hosts blocked by admins at startup or by request
        '''
        self.int_blocked = set()
        self.ext_blocked = set()

        if filename:
            self.load_from_file(filename)
        
    def add(self, dpid, source, destination=None):
        self.int_blocked.add((dpid, source, destination))
    
    def remove(self, dpid, source, destination=None):
        self.int_blocked.discard((dpid, source, destination))

    def load_from_file(self, filename):
        with open(filename) as file:
            data = json.load(file)
            
            for obj in data['blocked']:
                dpid = obj.get('dpid')
                source = obj.get('source')
                destination = obj.get('destination') if obj.get('destination') else None

                self.ext_blocked.add((dpid, source, destination))

    def values(self):
        return (self.int_blocked | self.ext_blocked)