"""
author : mohan
app_name : form_generator
"""

from django.test import TestCase

from rest_framework.test import APIClient

from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from .models import CreateProcess, FormDataInfo, FilledFormData, Case
# from .serializers import FilledDataInfoSerializer, CaseSerializer
from unittest.mock import patch
import json
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from .models import CreateProcess, FormDataInfo, FilledFormData, Case
from unittest.mock import patch

class FormGeneratorApiViewTestCase(TestCase):
    def setUp(self):
        print('2--')
        # Create a test client for making HTTP requests
        self.client = APIClient()
        print('3--')
        # Create a test object for  FormDataInfo(models)
        self.test_object = FormDataInfo.objects.create(heading='Test Heading', subheading='Test Subheading',
                                                       form_name='form_name', logo='Test Logo',
                                                       menu_name='Test Menu Name')
        print('4--')
        print('test_object--', self.test_object)
        # URL
        self.list_url = reverse('form_generator_create')
        print('self.list_url--', self.list_url)
        self.detail_url = reverse('form_generator_get', args=[self.test_object.id])
        print('self.detail_url--', self.detail_url)
        print('5--')

    def test_get_object_list(self):
        print('6--')
        response = self.client.get(self.list_url)
        print('response--1', response)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_get_object_detail(self):
        print('7--')
        response = self.client.get(self.detail_url)
        print('response--2', response)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    # def test_create_object(self):
    #     print('8--')
    #     data = {'heading': 'Test Heading', 'subheading': 'Test Subheading',
    #             'logo': 'Test Logo', 'menu_name': 'Test Menu Name', 'form_name': 'form_name'}
    #     print('data--', data)
    #     response = self.client.post(self.list_url, data, format='json')
    #     print('response--', response)
    #     self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_update_object(self):
        print('9--')
        data = {'form_json_schema': {
                                      "productId": 1,
                                      "productName": "A green door",
                                      "price": 12.50,
                                    }
                }
        response = self.client.put(self.detail_url, data, format='json')
        print('response--3', response)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_delete_object(self):
        print('10--')
        response = self.client.delete(self.detail_url)
        print('response--4', response)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

#

# Test case for creating the process

class CreateProcessViewTests(APITestCase):

    def setUp(self):
        # Set up initial data
        self.process = CreateProcess.objects.create(process_name="Test Process", participants={
            "executionFlow": {
                "flow_1": {
                    "currentStepId": "step_1",
                    "nextStepId": "step_2"
                }
            }
        })
        self.form_data_info = FormDataInfo.objects.create(Form_uid="step_1", form_json_schema='{"key": "value"}')
        self.url_list = reverse('create_process')
        self.url_detail = reverse('get_process', args=[self.process.pk])

    def test_get_all_processes(self):
        response = self.client.get(self.url_list)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['process_name'], self.process.process_name)

    def test_get_single_process(self):
        response = self.client.get(self.url_detail)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('key', response.data)

    def test_get_process_not_found(self):
        url = reverse('get_process', args=[999])
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.data['error'], 'Process not found')

    @patch('requests.post')
    def test_create_process_post(self, mock_post):
        mock_post.return_value.status_code = 200
        data = {
            "data_json": '{"field": "value"}'
        }
        response = self.client.post(self.url_detail, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(FilledFormData.objects.filter(processId=self.process.pk).exists())
        self.assertTrue(Case.objects.filter(processId=self.process.pk).exists())

    def test_create_process_invalid_request(self):
        data = {}
        response = self.client.post(self.url_detail, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Invalid request')

