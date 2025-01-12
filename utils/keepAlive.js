async function keepAlive(serviceURL) {
  try {
    const { default: fetch } = await import('node-fetch'); 
    const response = await fetch(serviceURL);

    if (response.ok) {
      console.log('Service at', serviceURL, 'activated successfully.');
    } else {
      console.error('Failed to activate service at', serviceURL, ':', response.statusText);
    }
  } catch (error) {
    console.error('Error activating service at', serviceURL, ':', error.message);
  }
}

module.exports = keepAlive;
