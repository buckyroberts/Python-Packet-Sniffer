

# Decode packet data
def decode_data(data):

    print('\n-- HTTP Header --\n')

    try:
        content = data.decode('utf-8')
        print(content)
    except:
        content = data.decode('utf-8', 'ignore').split('\r\n\r\n')
        print(str(content[0]))
        print('\n-- Body--\n\n' + str(content[1:]))
