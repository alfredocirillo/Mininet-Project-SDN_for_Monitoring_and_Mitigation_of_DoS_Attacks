import json

class Blocklist():
    def __init__(self, filename= None):
        '''
        Class to keep track of the blocked flows/hosts
        '''
        self.list = set()

        if filename:
            self.load_from_file(filename)
        
    def add(self, dpid, source, destination=None):
        self.list.add((dpid, source, destination))
    
    def remove(self, dpid, source, destination=None):
        self.list.discard((dpid, source, destination))

    def load_from_file(self, filename):
        with open(filename) as file:
            data = json.load(file)
            
            for obj in data['blocked']:
                dpid = obj.get('dpid')
                source = obj.get('source')
                destination = obj.get('destination') if obj.get('destination') else None

                self.list.add((dpid, source, destination))

    def values(self):
        return self.list