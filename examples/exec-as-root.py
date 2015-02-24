from ceilometer import utils as ceilometer_utils
from cinder import utils as cinder_utils
from neutron.agent.linux import utils as neutron_utils
from nova import utils as nova_utils

# Ceilometer
ceilometer_utils.execute('gcc --version')
ceilometer_utils.execute('gcc --version', run_as_root=False)
ceilometer_utils.execute('gcc --version', run_as_root=True)

# Cinder
cinder_utils.execute('gcc --version')
cinder_utils.execute('gcc --version', run_as_root=False)
cinder_utils.execute('gcc --version', run_as_root=True)

# Neutron
neutron_utils.execute('gcc --version')
neutron_utils.execute('gcc --version', run_as_root=False)
neutron_utils.execute('gcc --version', run_as_root=True)

# Nova
nova_utils.execute('gcc --version')
nova_utils.execute('gcc --version', run_as_root=False)
nova_utils.execute('gcc --version', run_as_root=True)
nova_utils.trycmd('gcc --version')
nova_utils.trycmd('gcc --version', run_as_root=True)
