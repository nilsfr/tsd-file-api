

from tsdfileapi.db import sqlite_init, SqliteBackend

from parser import SqlStatement

if __name__ == '__main__':
    test_data = [
        {
            'x': 1900,
            'y': 1,
            'z': 5,
            'b':[1, 2, 5, 1],
            'c': None,
            'd': 'string1'
        },
        {
            'y': 11,
            'z': 1,
            'c': [
                {
                    'h': 3,
                    'p': 99,
                    'w': False
                },
                {
                    'h': 32,
                    'p': False,
                    'w': True,
                    'i': {
                        't': [1,2,3]
                    }
                },
                {
                    'h': 0
                }
            ],
            'd': 'string2'
        },
        {
            'a': {
                'k1': {
                    'r1': [1, 2],
                    'r2': 2
                },
                'k2': ['val', 9]
            },
            'z': 0,
            'x': 88,
            'd': 'string3'
        },
        {
            'a': {
                'k1': {
                    'r1': [33, 200],
                    'r2': 90
                },
                'k2': ['val222', 90],
                'k3': [{'h': 0}]
            },
            'z': 10,
            'x': 107
        },
        {
            'x': 10
        }
    ]
    engine = sqlite_init('/tmp', name= 'file-api-test.db', builtin=True)
    db = SqliteBackend(engine, verbose=True)
    try:
        db.table_delete('mytable', '/mytable')
    except Exception:
        pass
    db.table_insert('mytable', test_data)
    select_uris = [
        # selections
        '/mytable',
        '/mytable?select=x',
        '/mytable?select=x,y',
        '/mytable?select=x,a.k1',
        '/mytable?select=x,a.k1.r1',
        '/mytable?select=a.k1.r1',
        '/mytable?select=a.k1.r1',
        '/mytable?select=b[1]',
        '/mytable?select=a,b[1]',
        '/mytable?select=a.k1.r1[0]',
        '/mytable?select=c[0].h',
        '/mytable?select=a.k3[0].h',
        '/mytable?select=x,y,c[0].h,b[1]',
        '/mytable?select=c[0].(h,p)',
        '/mytable?select=c[*].h',
        '/mytable?select=c[*].(h,p)',
        '/mytable?select=y,c[*].(h,i)',
        # filtering without groups
        '/mytable?select=x&where=z=eq.5,and:y=gt.0',
        '/mytable?where=x=not.like.*zap,and:y=not.is.null',
        '/mytable?select=z&where=a.k1.r2=eq.2',
        '/mytable?select=z&where=a.k1.r1[0]=eq.1',
        '/mytable?select=z&where=a.k3[0].h=eq.0',
        '/mytable?select=z&where=a.k1.r1[0]=eq.1,or:a.k3[0].h=eq.0',
        # filtering with groups
        '/mytable?where=(x=not.like.*zap,and:y=not.is.null)',
        '/mytable?where=((x=not.like.*zap,and:y=not.is.null),or:z=eq.0),and:z=eq.0',
        # filtering with in
        '/mytable?where=d=in.[string1,string2]',
        '/mytable?where=d=in.[string1,string2],and:c=not.is.null',
        # ordering
        '/mytable?order=y.desc',
        '/mytable?order=a.k1.r2.desc',
        '/mytable?order=b[0].asc',
        '/mytable?order=a.k3[0].h.asc',
        '/mytable?order=a.k3[0].h.desc',
        # with range
        '/mytable?select=x&range=0.2',
        '/mytable?range=2.3',
        # combined functionality
        '/mytable?select=x,c[*].(h,p),a.k1,b[0]&where=x=not.is.null,or:(y=gt.0,and:z=lt.100)&order=x.desc&range=1.2'
    ]
    update_uris = [
        # send data in payload, anchor on top-level key
        # one column per request, GET, PATCH sequence client side
        ('/mytable?set=x&where=z=eq.10', {'x': 5}),
        ('/mytable?set=y&where=z=eq.5', {'y': 6}),
    ]
    delete_uris = [
        '/mytable?where=z=not.is.null'
    ]
    # test regexes for single column selection strategies
    sql = SqlStatement('', '')
    # slice present
    assert not sql.idx_present.match('x')
    assert sql.idx_present.match('x[11]')
    assert sql.idx_present.match('x[1]')
    assert sql.idx_present.match('x[*]')
    # single slice
    assert not sql.idx_single.match('x[*]')
    assert sql.idx_single.match('x[1]')
    assert sql.idx_single.match('x[12]')
    # subselect present
    assert not sql.subselect_present.match('x[1]')
    assert sql.subselect_present.match('x[*].k')
    assert sql.subselect_present.match('x[1:9].(k,j)')
    # subselect single
    assert sql.subselect_single.match('x[*].k')
    # subselect mutliple
    assert not sql.subselect_multiple.match('x[*].k')
    # column quoting
    print(sql.quote_column_selection('x'))
    print(sql.quote_column_selection('x.y'))
    print(sql.quote_column_selection('y[1]'))
    print(sql.quote_column_selection('y[1].z'))
    print(sql.quote_column_selection('y[1].(z,a)'))
    print(sql.quote_column('erd.ys[1].(z,a)'))
    print(sql.quote_column('erd.ys[1].z'))
    print(sql.quote_column('"erd"."ys"[1]."z"'))
    print(sql.smart_split('x,y[1].(f,m,l),z'))
    print(sql.smart_split('x,y[1].k'))
    #print(sql.quote_column(',x,y[1].(z,a)')) - should error
    for uri in select_uris:
        try:
            print(uri)
            for row in db.table_select('mytable', uri):
                print(row)
            print()
        except Exception:
            pass
    for uri, data in update_uris:
        try:
            print(uri)
            db.table_update('mytable', uri, data)
            for row in db.table_select('mytable', '/mytable'):
                print(row)
            print()
        except Exception:
            pass
    for uri in delete_uris:
        print(uri)
        db.table_delete('mytable', uri)
        for row in db.table_select('mytable', '/mytable'):
            print(row)

