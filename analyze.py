import argparse
import docker
import json
import logging
import os
import requests

logging.basicConfig(format='%(asctime)s %(message)s', level=logging.DEBUG)
parser = argparse.ArgumentParser(description='Analyze Docker images on VirusTotal')
parser.add_argument('-f', '--file', metavar='<file>')
parser.add_argument('-t', '--tags',
                    metavar='<tags>',
                    type=int,
                    default=0,
                    help='number of tags to fetch per image (default: 0)')
parser.add_argument('--api-key',
                    metavar='<virustotal_api_key>',
                    help='VirusTotal API key')
args = parser.parse_args()

virustotal_file_scan_uri = 'https://www.virustotal.com/vtapi/v2/file/scan'
virustotal_file_scan_params = {'apikey': args.api_key}

def get_tags(image, max_tags):
    """

    :param image:
    :param max_tags:
    :return:
    """
    tags_list = []
    tags = []
    for i in range(1,1000):
        tags_resp = requests.get("https://hub.docker.com/v2/repositories/{}/tags/?page_size=25&page={}".format(image, i))
        tags_json = json.loads(tags_resp.content.decode('utf8'))

        # Don't make unnecessary requests if we have enough tags already
        tags += [result['name'] for result in tags_json['results']]
        if max_tags-len(tags_list) > 25:
            tags_list += tags
        else:
            tags_list += tags[:(max_tags-len(tags_list)) % 25]

        # If there are enough results already, break out of the loop
        if not tags_json['next'] or len(tags_list) >= max_tags:
            break

    return tags_list


def save_image(client, image, filename):
    logging.debug('Saving {} to disk'.format(image))
    i = docker_client.images.pull('{}'.format(image))
    with open('{}.tar'.format(filename), 'wb') as tarfile:
        for chunk in i.save():
            tarfile.write(chunk)


# Read images from file
logging.debug('Reading image names from file {}'.format(args.file))
with open(args.file, 'r') as f:
    images = dict.fromkeys([x.strip() for x in f.readlines()])
logging.debug('Successfully read {} image names from file'.format(len(images.keys())))

# Get tags for every image
for image in images:
    images[image] = get_tags(image, args.tags)
    logging.debug('Found {} tags for image {}'.format(len(images[image]), image))

# Analyze every image
docker_client = docker.from_env()
for image in images:
    for tag in images[image]:
        full_image_name = '{}:{}'.format(image, tag)
        filename = full_image_name.replace('/', '_')  # filename can't contain slashes

        # Save image to disk
        save_image(docker_client, image, filename)

        # Analyze Docker image in VirusTotal
        # files = {'file': (filename, open(filename, 'rb'))}
        # vt_response = requests.post(virustotal_file_scan_uri, files=files, params=virustotal_file_scan_params)

        # logging.debug('Removing {}'.format(filename))
        # os.remove(filename)
        docker_client.images.remove(full_image_name)
