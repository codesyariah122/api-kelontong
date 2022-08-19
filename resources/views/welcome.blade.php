<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">

  <title>{{env('APP_NAME')}}</title>
  <!-- Favicons -->
  <link href="assets/img/favicon.png" rel="icon">
  <link href="assets/img/apple-touch-icon.png" rel="apple-touch-icon">
  <!-- Fonts -->
  <link href="https://fonts.googleapis.com/css2?family=Nunito:wght@400;600;700&display=swap" rel="stylesheet">
  <link href="https://fonts.googleapis.com/css?family=Open+Sans:300,300i,400,400i,600,600i,700,700i|Nunito:300,300i,400,400i,600,600i,700,700i|Poppins:300,300i,400,400i,500,500i,600,600i,700,700i" rel="stylesheet">

  {{-- Vendor  --}}
  <link href="assets/vendor/aos/aos.css" rel="stylesheet">
  <link href="assets/vendor/bootstrap/css/bootstrap.min.css" rel="stylesheet">
  <link href="assets/vendor/bootstrap-icons/bootstrap-icons.css" rel="stylesheet">
  <link href="assets/vendor/glightbox/css/glightbox.min.css" rel="stylesheet">
  <link href="assets/vendor/remixicon/remixicon.css" rel="stylesheet">
  <link href="assets/vendor/swiper/swiper-bundle.min.css" rel="stylesheet">

  <link rel="stylesheet" type="text/css" href="assets/css/style.css">
</head>
<body>
  <!-- ======= Header ======= -->
  <header id="header" class="header fixed-top">
    <div class="container-fluid container-xl d-flex align-items-center justify-content-between">

      <a href="index.html" class="logo d-flex align-items-center">
        <img src="assets/img/logo.png" alt="">
        <span>{{env('APP_NAME')}}</span>
      </a>

      <nav id="navbar" class="navbar">
        <ul>
          <li><a class="nav-link scrollto" href="#contact">Contact</a></li>
          <li>
            @if (Route::has('login'))
            @auth
            <a href="{{ url('/home') }}" class="getstarted scrollto">Home</a>
            @else
            <a href="{{ route('login') }}" class="getstarted scrollto">
              <span>Login</span>
              <i class="bi bi-arrow-right"></i>
            </a>

            @if (Route::has('register'))
            <a href="{{ route('register') }}" class="getstarted scrollto">Register</a>
            @endif
            @endauth
            @endif
          </li>
        </ul>
        <i class="bi bi-list mobile-nav-toggle"></i>
      </nav><!-- .navbar -->

    </div>
  </header><!-- End Header -->
  <!-- ======= Hero Section ======= -->
  <section id="hero" class="hero d-flex align-items-center">

    <div class="container">
      <div class="row">
        <div class="col-lg-6 d-flex flex-column justify-content-center">
          <h1 data-aos="fade-up">
            Digitalkan Warung Anda Bersama Kami
          </h1>
          <h2 data-aos="fade-up" data-aos-delay="400">
            Toko Kelontong Digital
          </h2>

          <blockquote class="blockquote-footer mt-5">
            Bersama kembangkan ide bisnis
          </blockquote>
          <div data-aos="fade-up" data-aos-delay="600">
            <div class="text-center text-lg-start">
              <a href="{{env('FRONTEND_APP')}}" class="btn-get-started scrollto d-inline-flex align-items-center justify-content-center align-self-center">
                <span>Get Started</span>
                <i class="bi bi-arrow-right"></i>
              </a>
            </div>
          </div>
        </div>
        <div class="col-lg-6 hero-img" data-aos="zoom-out" data-aos-delay="200">
          <img src="assets/img/hero-img.png" class="img-fluid" alt="">
        </div>
      </div>
    </div>
  </section><!-- End Hero -->

  <main id="main">
    <!-- ======= About Section ======= -->
    <section id="about" class="about">

      <div class="container" data-aos="fade-up">
        <div class="row gx-0">

          <div class="col-lg-6 d-flex flex-column justify-content-center" data-aos="fade-up" data-aos-delay="200">
            <div class="content">
              <h3>Buka Warung Digital</h3>
              <h2>Ribet Cari Distributor Untuk Belanja Keperluan Warung Kamu ? </h2>
              <p>
                Di era teknologi informasi digital, berbisnis dengan memanfaatkan media daring bukan hal yang biasa banyak cara dan metode untuk berjualan mulai dari konvensional, digitalisasi bisnis dengan marketplace, bikin dengan jasa pembuatan website. Masih banyak kelemahan dan mungkin ada ketidak puasan yang didapat dengan berbisnis di media-media tersebut, bersama kami Toko Kelontong Online maksimalkan penjualan product di warung digital anda, dengan akses cepat pelayanan team kami yang akan selalu cekatan, kami siap menjadi partner untuk mengembangkan warung konvensional anda secara digital.
              </p>
              <div class="text-center text-lg-start">
                <a href="#" class="btn-read-more d-inline-flex align-items-center justify-content-center align-self-center">
                  <span>Read More</span>
                  <i class="bi bi-arrow-right"></i>
                </a>
              </div>
            </div>
          </div>

          <div class="col-lg-6 d-flex align-items-center" data-aos="zoom-out" data-aos-delay="200">
            <img src="{{asset('assets/img/klontong1.jpg')}}" class="img-fluid" alt="">
          </div>

        </div>
      </div>

    </section><!-- End About Section -->
  </main>

  <a href="#" class="back-to-top d-flex align-items-center justify-content-center"><i class="bi bi-arrow-up-short"></i></a>

  <!-- Vendor JS Files -->
  <script src="assets/vendor/purecounter/purecounter_vanilla.js"></script>
  <script src="assets/vendor/aos/aos.js"></script>
  <script src="assets/vendor/bootstrap/js/bootstrap.bundle.min.js"></script>
  <script src="assets/vendor/glightbox/js/glightbox.min.js"></script>
  <script src="assets/vendor/isotope-layout/isotope.pkgd.min.js"></script>
  <script src="assets/vendor/swiper/swiper-bundle.min.js"></script>
  <script src="assets/vendor/php-email-form/validate.js"></script>

  <!-- Template Main JS File -->
  <script src="assets/js/main.js"></script>
</body>
</html>
