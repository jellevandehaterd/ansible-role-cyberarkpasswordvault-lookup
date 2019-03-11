def format_list(list_, pattern):
    return [pattern % s for s in list_]

def remove_prefix_list(list_, pattern):
    result = []
    for line in list_:
        if line.startswith( pattern ):
            result.append(line[len(pattern):])

    return result

def remove_prefix(text, prefix):
    if text.startswith(prefix):
        return text[len(prefix):]
    return text

class FilterModule(object):
    def filters(self):
        return {
            'format_list': format_list,
            'remove_prefix_list': remove_prefix_list,
            'remove_prefix': remove_prefix,
        }