import uuid

SEARCH_GADGETS = {
    # RCE modules
    "os": set(),
    "subprocess": set(),
    "commands": set(),
    "pty": set(),
    "importlib": set(),
    "imp": set(),
    "sys": set(),
    "pip": set(),
    "pdb": set(),
    
    # RCE methods
    "system": set(),
    "popen": set(),
    "getstatusoutput": set(),
    "getoutput": set(),
    "call": set(),
    "Popen": set(),
    "popen": set(),
    "spawn": set(),
    "import_module": set(),
    "load_source": set(),
    "execfile": set(),
    "execute": set(),

    # Misc
    "__globals__": set(),
    "builtins": set(),
    "__builtins__": set(),
}

MAX_DEPTH = 3

def check_recursive(element, depth, prev_name):
    if depth > MAX_DEPTH:
        return
    
    for key in SEARCH_GADGETS:
        if (key in dir(element)):
            print(f"\t{prev_name}.{key}")
        elif type(element) is dict and key in element:
            print(f"\t{prev_name}[\"{key}\"]")
    
    # For attributes
    for new_element in dir(element):
        try:
            check_recursive(getattr(element, new_element), depth+1, f"{prev_name}.{new_element}")
        except:
            pass
    
    # For dicts
    if type(element) is dict:
        for new_element in element:
            check_recursive(element[new_element], depth + 1, f"{prev_name}[{new_element}]")


def main():
    # Example with uuid:
    total = [uuid]
    for _, element in enumerate(total):
        print(f"[Checking for {element.__name__}]\n")
        depth = 1
        check_recursive(element, depth, element.__name__)

if __name__ == "__main__":
    main()