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

MAX_DEPTH = 5

def check_recursive(element, depth, prev_name):
    if depth > MAX_DEPTH:
        return
    
    if "_" in prev_name:
        return
    
    # For attributes
    for new_element in dir(element):
        if (new_element in SEARCH_GADGETS):
            print(f"\t{prev_name}.{new_element}")
            continue
        try:
            check_recursive(getattr(element, new_element), depth+1, f"{prev_name}.{new_element}")
        except:
            pass
    
    # For dicts
    if type(element) is dict:
        for new_element in element:
            if (new_element in SEARCH_GADGETS):
                print(f"\t{prev_name}[\"{new_element}\"]")
                continue
            check_recursive(element[new_element], depth + 1, f"{prev_name}[\"{new_element}\"]")


def main():
    # Your module goes here
    module = __import__("uuid")

    # Example with uuid:
    total = dict()
    
    total.update({name: getattr(module, name) for name in dir(module)})
    
    total.update({name: func for name, func in module.__dict__.items() if not isinstance(func, list)})

    # TODO:
    #   Don't print module if no findings
    for name in total:
        depth = 1
        element = total[name]
        print(f"[Searching gadgets for {module.__name__}.{name}]\n")
        check_recursive(element, depth, f"{module.__name__}.{name}")
        print()

if __name__ == "__main__":
    main()