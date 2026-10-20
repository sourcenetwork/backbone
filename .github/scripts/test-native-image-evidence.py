#!/usr/bin/env python3
import copy
from pathlib import Path
import runpy
import unittest

module = runpy.run_path(str(Path(__file__).with_name('native-image-evidence.py')))
verify, Error = module['verify'], module['QualificationError']
SOURCE = '1' * 40
IMAGE_ID = 'sha256:' + '2' * 64


class NormalImages(unittest.TestCase):
    def image(self, role='orbis', curve='bls12-381'):
        image = module['REPOSITORIES'][role] + '@sha256:' + '3' * 64
        labels = {'org.opencontainers.image.revision': SOURCE}
        if role == 'orbis':
            labels.update({'io.sourcenetwork.orbis.backend': 'native',
                           'io.sourcenetwork.orbis.curve': curve,
                           'io.sourcenetwork.orbis.integration-features': 'false'})
        return image, {'Id': IMAGE_ID, 'RepoDigests': [image], 'Os': 'linux',
                       'Architecture': 'amd64', 'Config': {'Labels': labels,
                       'Entrypoint': ['orbis-node' if role == 'orbis' else 'verad'],
                       'Env': ['PRIVATE_VALUE=do-not-export']}}

    def test_both_curves_and_vera_bind_the_qualified_identity(self):
        for role, curve in [('orbis', 'bls12-381'), ('orbis', 'jubjub'), ('vera', None)]:
            with self.subTest(role=role, curve=curve):
                image, info = self.image(role, curve)
                result = verify(info, image, IMAGE_ID, SOURCE, role, curve)
                self.assertEqual(result['source'], SOURCE)
                self.assertEqual(result['image'], image)
                self.assertEqual(result['image_id'], IMAGE_ID)
                self.assertNotIn('Env', result)
                self.assertNotIn('PRIVATE_VALUE', str(result))

    def test_rejects_mutable_tags_foreign_repositories_and_invalid_sources(self):
        image, info = self.image()
        for selected, identifier, source in [
                (image.split('@')[0] + ':latest', IMAGE_ID, SOURCE),
                (image.replace('sourcenetwork/', 'untrusted/'), IMAGE_ID, SOURCE),
                (image, 'sha256:' + '4' * 64, SOURCE),
                (image, IMAGE_ID, '4' * 40),
                (image, IMAGE_ID, 'main'),
                (image, 'invalid', SOURCE)]:
            with self.subTest(image=selected, source=source), self.assertRaises(Error):
                verify(info, selected, identifier, source, 'orbis', 'bls12-381')

    def test_rejects_diagnostic_legacy_wrong_curve_and_integration_images(self):
        image, original = self.image()
        for key, value in [
                ('io.sourcenetwork.orbis.backend', 'cosmos'),
                ('io.sourcenetwork.orbis.curve', 'jubjub'),
                ('io.sourcenetwork.orbis.integration-features', 'true'),
                ('io.sourcenetwork.orbis.unsafe-testing', 'true'),
                ('org.opencontainers.image.revision', '5' * 40)]:
            info = copy.deepcopy(original)
            info['Config']['Labels'][key] = value
            with self.subTest(label=key), self.assertRaises(Error):
                verify(info, image, IMAGE_ID, SOURCE, 'orbis', 'bls12-381')

    def test_rejects_wrong_content_platform_and_entrypoint(self):
        image, original = self.image()
        for key, value in [('RepoDigests', []), ('RepoDigests', 1),
                           ('RepoDigests', image), ('Architecture', 'arm64'),
                           ('Os', 'windows'), ('Id', 'sha256:' + '6' * 64),
                           ('Config', {'Labels': original['Config']['Labels'],
                                       'Entrypoint': ['sh']})]:
            info = copy.deepcopy(original)
            info[key] = value
            with self.subTest(field=key), self.assertRaises(Error):
                verify(info, image, IMAGE_ID, SOURCE, 'orbis', 'bls12-381')

    def test_rejects_missing_metadata_and_invalid_role_curve_pairs(self):
        image, info = self.image()
        for candidate in [None, [], {}, dict(info, Config=None),
                          dict(info, Config={'Labels': None})]:
            with self.subTest(metadata=candidate), self.assertRaises(Error):
                verify(candidate, image, IMAGE_ID, SOURCE, 'orbis', 'bls12-381')
        for role, curve in [('untrusted', None), ('orbis', None), ('orbis', 'invalid')]:
            with self.subTest(role=role, curve=curve), self.assertRaises(Error):
                verify(info, image, IMAGE_ID, SOURCE, role, curve)
        image, info = self.image('vera', None)
        with self.assertRaises(Error):
            verify(info, image, IMAGE_ID, SOURCE, 'vera', 'bls12-381')


if __name__ == '__main__':
    unittest.main()
