export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const code = searchParams.get('code');

  if (!code) {
    return new Response('Missing authorization code', {
      status: 400,
    });
  }

  console.log('[Callback] Code:', code);

  try {
    // Complete the auth flow...

    return new Response(null, {
      status: 302,
      headers: {
        Location: '/', // Or wherever you want to redirect after auth
      },
    });
  } catch (error) {
    console.error('Auth callback error:', error);
    return new Response('Authorization failed', {
      status: 500,
    });
  }
}
